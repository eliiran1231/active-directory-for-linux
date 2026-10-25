using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class LdapConnectionProvider
{
    // Only the audited, operation-owned FindOne path may use this subset.
    // Native validation: 40214586987, 31/31 on net8/net10. This is not a
    // general provider/referral switch or a referral-destination allowlist.
    internal static bool ContextScopedProductionEnabled => OperatingSystem.IsWindows();

    internal static bool IsContextScopedReadConfiguration(LdapConnectionOptions options,
        ReferralChasingOption referrals, SearchRequest request) =>
        referrals == ReferralChasingOption.External &&
        options.Host == "127.0.0.1" && options.Port > 0 && options.Port <= 65535 && options.UseSsl &&
        !options.UseStartTls && !options.SkipCertificateCheck && !options.Signing && !options.Sealing &&
        options.AuthenticationType == AuthType.Basic && !options.IsAnonymous &&
        !string.IsNullOrEmpty(options.BindDn) && !string.IsNullOrEmpty(options.BindPassword) &&
        request.Scope == System.DirectoryServices.Protocols.SearchScope.Base && request.Controls.Count == 0;

    // Audited caller: DirectorySearcher.FindOne only, with no controls/overrides.
    // No connection/delegate escapes. Schema reads use their own explicitly fresh External lease.
    internal static SearchResponse SendContextScopedRead(LdapConnectionOptions options,
        ReferralChasingOption referrals, SearchRequest request, TimeSpan? requestTimeout,
        DirectoryEntry.BindingAuthority authority, bool preferFresh, long minimumGeneration)
    {
        if (!ContextScopedProductionEnabled || !OperatingSystem.IsWindows() ||
            !IsContextScopedReadConfiguration(options, referrals, request))
            throw new InvalidOperationException("Windows context-scoped read is not enabled.");
        return SendContextScopedReadCore(options, referrals, request, requestTimeout, authority, preferFresh, minimumGeneration);
    }

    // Standalone native validation must exercise this SAME core and token query.
    // Existing diagnostics may not grant general production eligibility.
    internal static SearchResponse SendContextScopedReadDiagnostic(LdapConnectionOptions options,
        SearchRequest request, CancellationToken cancellationToken = default)
    {
        using var diagnostic = new ContextScopedReadDiagnostic();
        return SendContextScopedReadDiagnostic(options, request, diagnostic, cancellationToken: cancellationToken);
    }

    internal static SearchResponse SendContextScopedReadDiagnostic(LdapConnectionOptions options,
        SearchRequest request, ContextScopedReadDiagnostic diagnostic, DirectoryEntry.BindingAuthority? authority = null,
        TimeSpan? timeout = null, bool preferFresh = false, long minimumGeneration = 0, CancellationToken cancellationToken = default)
    {
        ContextScopedReadDiagnostic.Validate();
        if (!IsContextScopedReadConfiguration(options, ReferralChasingOption.External, request))
            throw new InvalidOperationException("Outside scoped diagnostic configuration.");
        return SendContextScopedReadCore(options, ReferralChasingOption.External, request, timeout, authority,
            preferFresh, minimumGeneration, cancellationToken, diagnostic);
    }

    private sealed class DiagnosticRetirement : Exception { }
    internal static void RetireContextScopedDiagnostic(ConnectionKey key)
    {
        ContextScopedReadDiagnostic.Validate();
        // Existing freshness semantics drain the exact idle key. The factory
        // deliberately stops before allocating a connection: no cleanup binds.
        try { using var unused = Pool.Acquire(key, () => throw new DiagnosticRetirement(), reusable: false, preferFresh: true); }
        catch (DiagnosticRetirement) { }
    }

    private static SearchResponse SendContextScopedReadCore(LdapConnectionOptions options,
        ReferralChasingOption referrals, SearchRequest request, TimeSpan? requestTimeout,
        DirectoryEntry.BindingAuthority? authority, bool preferFresh, long minimumGeneration,
        CancellationToken cancellationToken = default, ContextScopedReadDiagnostic? diagnostic = null)
    {
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        return ContextScopedRequest.Execute(WindowsLdapContextQuery.Capture, (context, reusable) =>
        {
            var key = ConnectionKey.CreateContextScoped(snapshot, referrals, context);
            diagnostic?.Track(key);
            var lease = Pool.Acquire(key, () => LdapConnectionFactory.ConfigureOwned(
                LdapConnectionFactory.Create(snapshot), connection =>
                {
                    LdapConnectionFactory.ConfigureReferralChasing(connection, referrals);
                    connection.Bind();
                }), cancellationToken, reusable, preferFresh, minimumGeneration);
            return new ScopedSearchLease(lease, request, requestTimeout ?? snapshot.Timeout, authority);
        }, cancellationToken, diagnostic?.Boundary);
    }

    private sealed class ScopedSearchLease(
        BoundedConnectionPool<ConnectionKey, LdapConnection>.Lease lease,
        SearchRequest request, TimeSpan timeout, DirectoryEntry.BindingAuthority? authority)
        : IContextRequestLease<SearchResponse>
    {
        public void Prepare() => authority?.Validate();
        public SearchResponse Send() => (SearchResponse)lease.Value.SendRequest(request, timeout);
        public void Invalidate() => lease.Invalidate();
        public void Dispose() => lease.Dispose();
    }
}
