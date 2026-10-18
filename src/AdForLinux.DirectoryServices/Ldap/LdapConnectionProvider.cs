using System.DirectoryServices.Protocols;
using System.Security.Cryptography;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>Pool only audited operation-owned sessions; raw factory ownership remains explicit.</summary>
internal static class LdapConnectionProvider
{
    private static readonly BoundedConnectionPool<ConnectionKey, LdapConnection> Pool = new();
    internal static (int Total, int Keys, int Waiting, long Created, long Reused, long Destroyed, long Failures, long Waits, long Timeouts) Snapshot => Pool.Snapshot;

    static LdapConnectionProvider()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Pool.Dispose();
        System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(typeof(LdapConnectionProvider).Assembly)!.Unloading += _ => Pool.Dispose();
    }

    internal static bool CanReuse(LdapConnectionOptions options) =>
        options.AuthenticationType == AuthType.Basic && !options.IsAnonymous &&
        !string.IsNullOrEmpty(options.BindDn) && !string.IsNullOrEmpty(options.BindPassword);

    internal static long NewGeneration() => Pool.NewGeneration();
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LdapConnection, Session> Active = new();

    internal static Session Acquire(LdapConnectionOptions options, CancellationToken cancellationToken = default,
        ReferralChasingOption referrals = ReferralChasingOption.None, bool preferFresh = false, long minimumGeneration = 0)
        => AcquireBatch(options, 1, cancellationToken, referrals, preferFresh, minimumGeneration)[0];

    internal static Session[] AcquireBatch(LdapConnectionOptions options, int count, CancellationToken cancellationToken = default,
        ReferralChasingOption referrals = ReferralChasingOption.None, bool preferFresh = false, long minimumGeneration = 0)
    {
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        // Referral targets can retain native authentication/session state that the
        // managed API cannot inspect or reset. Bound their handles but do not reuse.
        var reusable = CanReuse(snapshot) && referrals == ReferralChasingOption.None;
        var key = ConnectionKey.Create(snapshot, referrals);
        var leases = Pool.AcquireBatch(key, count, () =>
        {
            var connection = LdapConnectionFactory.Create(snapshot);
            return LdapConnectionFactory.ConfigureOwned(connection, value =>
            {
                LdapConnectionFactory.ConfigureReferralChasing(value, referrals);
                value.Bind();
            });
        }, cancellationToken, reusable, preferFresh, minimumGeneration);
        return leases.Select(lease => new Session(lease)).ToArray();
    }

    internal static Session AcquireValidation(LdapConnectionOptions options)
    {
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        // Validation must perform the original fresh bind, even when a healthy
        // session for exactly these credentials is idle. It still consumes capacity.
        return new Session(Pool.Acquire(ConnectionKey.Create(snapshot, ReferralChasingOption.All),
            () => LdapConnectionFactory.CreateBound(snapshot), reusable: false));
    }

    internal static Session[] AcquirePair(LdapConnectionOptions first, LdapConnectionOptions second,
        Func<TimeSpan> remaining, CancellationToken cancellationToken)
    {
        OfflineTestGuard.RequireLiveAccess();
        var requests = new[] { first.Clone(), second.Clone() }.Select(snapshot =>
            new BoundedConnectionPool<ConnectionKey, LdapConnection>.Request(
                ConnectionKey.Create(snapshot, ReferralChasingOption.None), () =>
                {
                    // The key uses stable configuration; the current deadline limits
                    // this bind only and never fragments the pool into timeout keys.
                    var connection = LdapConnectionFactory.Create(snapshot.Clone(remaining()));
                    return LdapConnectionFactory.ConfigureOwned(connection, value =>
                    {
                        LdapConnectionFactory.ConfigureReferralChasing(value, ReferralChasingOption.None);
                        value.Bind();
                        value.Timeout = snapshot.Timeout;
                    });
                }, CanReuse(snapshot))).ToArray();
        return Pool.AcquireMany(requests, cancellationToken).Select(lease => new Session(lease)).ToArray();
    }

    internal static void ReportFailure(LdapConnection connection, Exception error)
    {
        if (IsConnectionFailure(error) && Active.TryGetValue(connection, out var session)) session.Invalidate();
    }

    internal static DirectoryResponse SendRequestTracked(this LdapConnection connection, DirectoryRequest request)
    {
        try { return connection.SendRequest(request); }
        catch (Exception error) { ReportFailure(connection, error); throw; }
    }

    internal static TResult Execute<TResult>(LdapConnectionOptions options, Func<LdapConnection, TResult> operation)
    {
        using var session = Acquire(options);
        return session.Execute(operation);
    }

    internal sealed class Session : IDisposable
    {
        private readonly BoundedConnectionPool<ConnectionKey, LdapConnection>.Lease lease;
        private readonly LdapConnection connection;
        private int disposed;
        internal Session(BoundedConnectionPool<ConnectionKey, LdapConnection>.Lease lease)
        { this.lease = lease; connection = lease.Value; Active.Add(connection, this); }
        internal LdapConnection Connection => lease.Value;
        internal void Invalidate() => lease.Invalidate();
        internal TResult Execute<TResult>(Func<LdapConnection, TResult> operation)
        {
            try { return operation(lease.Value); }
            catch (Exception error) { ReportFailure(connection, error); throw; }
        }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            Active.Remove(connection);
            lease.Dispose();
        }
    }

    internal static bool IsConnectionFailure(Exception error)
    {
        if (error is DirectoryOperationException operation)
            return operation.Response is null || operation.Response.ResultCode is ResultCode.Unavailable or ResultCode.ProtocolError;
        if (error is DirectoryServicesCOMException { InnerException: DirectoryOperationException protocol })
            return IsConnectionFailure(protocol);
        // Unknown exceptions may interrupt the request before completion. Never replay it.
        return true;
    }

    internal sealed class ConnectionKey : IEquatable<ConnectionKey>
    {
        private static readonly byte[] Secret = RandomNumberGenerator.GetBytes(32);
        private readonly string digest;
        private ConnectionKey(string digest) => this.digest = digest;
        internal static ConnectionKey Create(LdapConnectionOptions options, ReferralChasingOption referrals)
        {
            using var data = new MemoryStream(checked(100 + 2 * (options.Host.Length +
                (options.BindDn?.Length ?? 0) + (options.BindPassword?.Length ?? 0))));
            using (var writer = new BinaryWriter(data, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                WriteNullable(writer, options.Host); writer.Write(options.Port);
                writer.Write(options.UseSsl); writer.Write(options.UseStartTls); writer.Write(options.SkipCertificateCheck);
                writer.Write((int)options.AuthenticationType); writer.Write(options.Signing); writer.Write(options.Sealing);
                WriteNullable(writer, options.BindDn); WriteNullable(writer, options.BindPassword);
                writer.Write(options.Timeout.Ticks); writer.Write((int)referrals);
            }
            var bytes = data.GetBuffer().AsSpan(0, checked((int)data.Length));
            try { return new(Convert.ToHexString(HMACSHA256.HashData(Secret, bytes))); }
            finally { CryptographicOperations.ZeroMemory(data.GetBuffer()); }
        }
        private static void WriteNullable(BinaryWriter writer, string? value)
        {
            writer.Write(value is not null);
            if (value is null) return;
            // Preserve exact .NET strings. UTF-8 replacement fallback would collapse
            // distinct malformed surrogate sequences into the same credential key.
            writer.Write(value.Length);
            foreach (var character in value) writer.Write((ushort)character);
        }
        public bool Equals(ConnectionKey? other) => other is not null && digest == other.digest;
        public override bool Equals(object? obj) => obj is ConnectionKey key && Equals(key);
        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(digest);
        public override string ToString() => "LDAP connection configuration (redacted)";
    }
}
