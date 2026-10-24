using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    internal ConnectionLease AcquireContextScopedReadSchemaConnection(BindingAuthority authority)
        => AcquireConnection(authority.Validate, ReferralChasingOption.External, schema: true, forceFresh: true);

    internal bool TryContextScopedRead(SearchRequest request, ReferralChasingOption referrals,
        TimeSpan? timeout, BindingAuthority authority, out SearchResponse? response, ContextScopedReadDiagnostic? diagnostic = null)
    {
        response = null;
        if (diagnostic is not null) ContextScopedReadDiagnostic.Validate();
        if ((diagnostic is null && !LdapConnectionProvider.ContextScopedProductionEnabled) || !OperatingSystem.IsWindows()) return false;
        void Validate() { ThrowIfDisposed(); authority.Validate(); }
        var generation = IdentityLifetime.Capture(Validate);
        var snapshot = IdentityLifetime.Checked(generation, Validate, () =>
            (Options: BuildOptions(), Fresh: _freshConnectionRequired, Minimum: _minimumConnectionGeneration,
             Existing: _connection is not null || _schemaConnection is not null || OperationSessionFactory is not null));
        if (snapshot.Existing || !LdapConnectionProvider.IsContextScopedReadConfiguration(snapshot.Options, referrals, request)) return false;
        response = diagnostic is null
            ? LdapConnectionProvider.SendContextScopedRead(snapshot.Options, referrals, request, timeout,
                authority, snapshot.Fresh, snapshot.Minimum)
            : LdapConnectionProvider.SendContextScopedReadDiagnostic(snapshot.Options, request, diagnostic,
                authority, timeout, snapshot.Fresh, snapshot.Minimum);
        IdentityLifetime.Checked(generation, Validate, () =>
        { _freshConnectionRequired = false; _hasOperationConnection = true; return true; });
        return true;
    }
}
