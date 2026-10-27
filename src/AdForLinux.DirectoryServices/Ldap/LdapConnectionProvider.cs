using System.DirectoryServices.Protocols;
using System.Security.Cryptography;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>Pool only audited operation-owned sessions; raw factory ownership remains explicit.</summary>
internal static partial class LdapConnectionProvider
{
    private static readonly BoundedConnectionPool<ConnectionKey, BoundLdapSession> Pool = new();
    internal static (int Total, int Keys, int Waiting, long Created, long Reused, long Destroyed, long Failures, long Waits, long Timeouts) Snapshot => Pool.Snapshot;

    static LdapConnectionProvider()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Pool.Dispose();
        System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(typeof(LdapConnectionProvider).Assembly)!.Unloading += _ => Pool.Dispose();
    }

    internal static bool CanReuse(LdapConnectionOptions options,
        ReferralChasingOption referrals = ReferralChasingOption.None) =>
        new LdapAuthenticationSource(options).Freshness(referrals) == LdapSessionFreshness.CompatibleEstablishedSession;

    internal static long NewGeneration() => Pool.NewGeneration();
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LdapConnection, Session> Active = new();

    internal static Session Acquire(LdapConnectionOptions options, CancellationToken cancellationToken = default,
        ReferralChasingOption referrals = ReferralChasingOption.None, bool preferFresh = false, long minimumGeneration = 0)
        => AcquireBatch(options, 1, cancellationToken, referrals, preferFresh, minimumGeneration)[0];

    internal static Session[] AcquireBatch(LdapConnectionOptions options, int count, CancellationToken cancellationToken = default,
        ReferralChasingOption referrals = ReferralChasingOption.None, bool preferFresh = false, long minimumGeneration = 0)
    {
        if (options.RestrictedKerberos is not null)
            return LdapRestrictedOperation.Acquire(options, count, referrals, cancellationToken);
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        // Retain the entire native session, including referral children, only
        // under its exact immutable credentials and referral/transport settings.
        var authentication = new LdapAuthenticationSource(snapshot);
        var reusable = authentication.Freshness(referrals) == LdapSessionFreshness.CompatibleEstablishedSession;
        var key = ConnectionKey.Create(snapshot, referrals);
        var leases = Pool.AcquireBatch(key, count, () => authentication.Bind(referrals),
            cancellationToken, reusable, preferFresh, minimumGeneration);
        return leases.Select(lease => new Session(lease)).ToArray();
    }

    internal static Session AcquireValidation(LdapConnectionOptions options)
    {
        options.RestrictedKerberos?.RefuseUnavailableBackend(options);
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        // Validation must perform the original fresh bind, even when a healthy
        // session for exactly these credentials is idle. It still consumes capacity.
        return new Session(Pool.Acquire(ConnectionKey.Create(snapshot, ReferralChasingOption.All),
            () => new LdapAuthenticationSource(snapshot).Bind(null), reusable: false));
    }

    internal static Session[] AcquirePair(LdapConnectionOptions first, LdapConnectionOptions second,
        Func<TimeSpan> remaining, CancellationToken cancellationToken)
    {
        if (first.RestrictedKerberos is not null || second.RestrictedKerberos is not null)
        {
            if (first.RestrictedKerberos is null || !ReferenceEquals(first.RestrictedKerberos, second.RestrictedKerberos) ||
                !ConnectionKey.Create(first, ReferralChasingOption.None).Equals(ConnectionKey.Create(second, ReferralChasingOption.None)))
                throw new PlatformNotSupportedException("Restricted paired admission requires the same profile and complete connection recipe.");
            return LdapRestrictedOperation.Acquire(first, 2, ReferralChasingOption.None, cancellationToken, remaining());
        }
        OfflineTestGuard.RequireLiveAccess();
        var requests = new[] { first.Clone(), second.Clone() }.Select(snapshot =>
        {
            var authentication = new LdapAuthenticationSource(snapshot);
            return new BoundedConnectionPool<ConnectionKey, BoundLdapSession>.Request(
                ConnectionKey.Create(snapshot, ReferralChasingOption.None),
                () => authentication.Bind(ReferralChasingOption.None, remaining()),
                authentication.Freshness(ReferralChasingOption.None) == LdapSessionFreshness.CompatibleEstablishedSession);
        }).ToArray();
        return Pool.AcquireMany(requests, cancellationToken).Select(lease => new Session(lease)).ToArray();
    }

    internal static bool IsManagedSession(LdapConnection connection) => Active.TryGetValue(connection, out _);

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

    internal static TResult ExecuteTransport<TResult>(LdapConnectionOptions options, Func<ILdapRequestTransport, TResult> operation)
    {
        using var session = Acquire(options);
        return session.ExecuteTransport(operation);
    }

    internal sealed class Session : IDisposable
    {
        private readonly BoundedConnectionPool<ConnectionKey, BoundLdapSession>.Lease? lease;
        private readonly BoundLdapSession? owned;
        private readonly Action? invalidateOwned, validateOwned;
        private readonly LdapConnection? connection;
        private int disposed;
        private Action? afterDispose;
        internal Session(BoundedConnectionPool<ConnectionKey, BoundLdapSession>.Lease lease, Action? afterDispose = null)
        { this.lease = lease; this.afterDispose = afterDispose; connection = lease.Value.ProtocolsConnection; if (connection is not null) Active.Add(connection, this); }
        internal Session(BoundLdapSession owned, Action invalidate, Action validate)
        { this.owned = owned; invalidateOwned = invalidate; validateOwned = validate; }
        private BoundLdapSession Value
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
                validateOwned?.Invoke();
                return owned ?? lease!.Value;
            }
        }
        internal LdapConnection Connection => Value.Connection;
        internal void Invalidate()
        { if (lease is not null) lease.Invalidate(); else invalidateOwned!.Invoke(); }
        internal TResult Execute<TResult>(Func<LdapConnection, TResult> operation)
        {
            var value = Value;
            try { return operation(value.Connection); }
            catch (Exception error) { if (IsConnectionFailure(error)) Invalidate(); throw; }
        }
        internal TResult ExecuteTransport<TResult>(Func<ILdapRequestTransport, TResult> operation)
        {
            var value = Value;
            try { return operation(value.Transport); }
            catch (Exception error) { if (IsConnectionFailure(error)) Invalidate(); throw; }
        }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try
            {
                if (connection is not null) Active.Remove(connection);
            }
            finally
            {
                try { if (lease is not null) lease.Dispose(); else owned!.Dispose(); }
                finally { Interlocked.Exchange(ref afterDispose, null)?.Invoke(); }
            }
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
            => CreateCore(options, referrals, false, null);
        internal static ConnectionKey CreateContextScoped(LdapConnectionOptions options, ReferralChasingOption referrals, WindowsLdapContext? context)
            => CreateCore(options, referrals, true, context);
        private static ConnectionKey CreateCore(LdapConnectionOptions options, ReferralChasingOption referrals, bool scoped, WindowsLdapContext? context)
        {
            using var data = new MemoryStream(checked((scoped ? 256 : 100) + 2 * (options.Host.Length +
                (options.BindDn?.Length ?? 0) + (options.BindPassword?.Length ?? 0))));
            using (var writer = new BinaryWriter(data, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                WriteNullable(writer, options.Host); writer.Write(options.Port);
                writer.Write(options.UseSsl); writer.Write(options.UseStartTls); writer.Write(options.SkipCertificateCheck);
                writer.Write((int)options.AuthenticationType); writer.Write(options.Signing); writer.Write(options.Sealing);
                WriteNullable(writer, options.BindDn); WriteNullable(writer, options.BindPassword);
                writer.Write(options.Timeout.Ticks); writer.Write((int)referrals);
                if (scoped)
                {
                    writer.Write("WindowsContextScopedRead/v1");
                    writer.Write(context.HasValue);
                    if (context is { } value)
                    {
                        writer.Write(value.TokenId); writer.Write(value.AuthenticationId); writer.Write(value.ModifiedId);
                        writer.Write(value.TokenType); writer.Write(value.ImpersonationLevel); writer.Write(value.ThreadToken);
                    }
                }
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
