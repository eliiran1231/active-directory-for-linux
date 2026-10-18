using System.DirectoryServices.Protocols;
using System.Security.Cryptography;
using System.Text;

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

    internal static Session Acquire(LdapConnectionOptions options, CancellationToken cancellationToken = default)
    {
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        var reusable = CanReuse(snapshot);
        // Sharing an accounting key never shares an authentication session when reuse is disabled.
        var key = ConnectionKey.Create(snapshot, ReferralChasingOption.None);
        var lease = Pool.Acquire(key, () =>
        {
            var connection = LdapConnectionFactory.Create(snapshot);
            return LdapConnectionFactory.ConfigureOwned(connection, value =>
            {
                LdapConnectionFactory.ConfigureReferralChasing(value, ReferralChasingOption.None);
                value.Bind();
            });
        }, cancellationToken, reusable);
        return new Session(lease);
    }

    internal static TResult Execute<TResult>(LdapConnectionOptions options, Func<LdapConnection, TResult> operation)
    {
        using var session = Acquire(options);
        return session.Execute(operation);
    }

    internal sealed class Session(BoundedConnectionPool<ConnectionKey, LdapConnection>.Lease lease) : IDisposable
    {
        internal TResult Execute<TResult>(Func<LdapConnection, TResult> operation)
        {
            try { return operation(lease.Value); }
            catch (Exception error)
            {
                if (IsConnectionFailure(error)) lease.Invalidate();
                throw;
            }
        }
        public void Dispose() => lease.Dispose();
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
            using var data = new MemoryStream();
            using (var writer = new BinaryWriter(data, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(options.Host); writer.Write(options.Port);
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
        { writer.Write(value is not null); if (value is not null) writer.Write(value); }
        public bool Equals(ConnectionKey? other) => other is not null && digest == other.digest;
        public override bool Equals(object? obj) => obj is ConnectionKey key && Equals(key);
        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(digest);
        public override string ToString() => "LDAP connection configuration (redacted)";
    }
}
