using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    private long _minimumConnectionGeneration;
    private bool _freshConnectionRequired;
    private bool _hasOperationConnection;

    // Raw retained fields remain a compatibility seam for existing controlled
    // transports. Production operations own these short-lived leases instead.
    internal sealed class ConnectionLease : IDisposable
    {
        private readonly LdapConnectionProvider.Session? session;
        private readonly LdapConnection connection;
        internal ConnectionLease(LdapConnection connection) => this.connection = connection;
        internal ConnectionLease(LdapConnectionProvider.Session session)
        { this.session = session; connection = session.Connection; }
        internal LdapConnection Connection => session?.Connection ?? connection;
        internal void Invalidate() => session?.Invalidate();
        public void Dispose() => session?.Dispose();
    }

    private DirectoryEntry CopyConnectionFreshnessTo(DirectoryEntry copy)
    {
        copy._minimumConnectionGeneration = _minimumConnectionGeneration;
        copy._freshConnectionRequired = _freshConnectionRequired;
        copy.OperationSessionFactory = OperationSessionFactory;
        return copy;
    }

    internal Func<LdapConnectionOptions, int, ReferralChasingOption, bool, long, LdapConnectionProvider.Session[]>? OperationSessionFactory { get; set; }

    internal ConnectionLease AcquireConnection(Action? validate = null, ReferralChasingOption? referrals = null, bool schema = false, bool forceFresh = false)
        => AcquireConnections(1, validate, referrals, schema, forceFresh)[0];

    internal ConnectionLease[] AcquireConnections(int count, Action? validate = null,
        ReferralChasingOption? referrals = null, bool schema = false, bool forceFresh = false)
    {
        void Validate() { ThrowIfDisposed(); validate?.Invoke(); }
        var generation = IdentityLifetime.Capture(Validate);
        var snapshot = IdentityLifetime.Checked(generation, Validate, () =>
            (Options: BuildOptions(), Referral: referrals ?? Options.Referral,
             Minimum: _minimumConnectionGeneration, Fresh: _freshConnectionRequired || forceFresh,
             Existing: forceFresh ? null : schema ? _schemaConnection : _connection, Schema: forceFresh ? null : _schemaConnection));
        if (snapshot.Existing is not null)
            return Enumerable.Range(0, count).Select(index =>
                new ConnectionLease(index == 0 ? snapshot.Existing : snapshot.Schema ?? snapshot.Existing)).ToArray();
        var sessions = LdapExceptionTranslator.Execute(() => OperationSessionFactory is { } open
            ? open(snapshot.Options, count, snapshot.Referral, snapshot.Fresh, snapshot.Minimum)
            : LdapConnectionProvider.AcquireBatch(snapshot.Options, count, referrals: snapshot.Referral,
                preferFresh: snapshot.Fresh, minimumGeneration: snapshot.Minimum));
        try
        {
            IdentityLifetime.Checked(generation, Validate, () => { _freshConnectionRequired = false; _hasOperationConnection = true; return true; });
            return sessions.Select(session => new ConnectionLease(session)).ToArray();
        }
        catch
        {
            foreach (var session in sessions) { session.Invalidate(); session.Dispose(); }
            throw;
        }
    }

    internal LdapConnection SchemaConnectionForOperation(LdapConnection connection) => _schemaConnection ?? connection;

    internal ConnectionLease AcquireConfigurationConnection(DirectoryEntryConfiguration owner)
    {
        BeforeConfigurationConnection?.Invoke();
        return AcquireConnection(owner.ValidateOwner);
    }
}
