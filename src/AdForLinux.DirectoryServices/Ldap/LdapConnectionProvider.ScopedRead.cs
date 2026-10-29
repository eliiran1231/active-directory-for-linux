using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class LdapConnectionProvider
{
    // Only the audited, operation-owned FindOne path may use this subset.
    // This is not a general provider/referral switch or a target allowlist.
    internal static bool ContextScopedProductionEnabled => OperatingSystem.IsWindows();

    internal static bool IsContextScopedReadConfiguration(LdapConnectionOptions options,
        ReferralChasingOption referrals, SearchRequest request) =>
        referrals == ReferralChasingOption.External &&
        IsExplicitWindowsLdapsHost(options.Host) && options.Port > 0 && options.Port <= 65535 && options.UseSsl &&
        !options.UseStartTls && !options.SkipCertificateCheck && !options.Signing && !options.Sealing &&
        options.AuthenticationType == AuthType.Basic && !options.IsAnonymous &&
        !string.IsNullOrEmpty(options.BindDn) && !string.IsNullOrEmpty(options.BindPassword) &&
        request.Controls.Count == 0 && (request.Scope == System.DirectoryServices.Protocols.SearchScope.Base ||
            (request.Scope is System.DirectoryServices.Protocols.SearchScope.OneLevel or System.DirectoryServices.Protocols.SearchScope.Subtree &&
             request.SizeLimit == 1));

    // Eligibility only: preserve the exact caller string for native resolution,
    // TLS verification and the key. DNS names can still select multiple DCs;
    // this neither pins a destination nor changes WinLDAP discovery options.
    internal static bool IsExplicitWindowsLdapsHost(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253) return false;
        if (System.Net.IPAddress.TryParse(host, out var address))
            return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                string.Equals(address.ToString(), host, StringComparison.Ordinal);
        bool letter = false;
        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            foreach (char c in label)
            {
                if (char.IsAsciiLetter(c)) letter = true;
                else if (!char.IsAsciiDigit(c) && c != '-') return false;
            }
        }
        return letter; // Do not reinterpret noncanonical numeric IP spellings as DNS.
    }

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

    private static SearchResponse SendContextScopedReadCore(LdapConnectionOptions options,
        ReferralChasingOption referrals, SearchRequest request, TimeSpan? requestTimeout,
        DirectoryEntry.BindingAuthority? authority, bool preferFresh, long minimumGeneration,
        CancellationToken cancellationToken = default)
    {
        OfflineTestGuard.RequireLiveAccess();
        var snapshot = options.Clone();
        return ContextScopedRequest.Execute(WindowsLdapContextQuery.Capture, (context, reusable) =>
        {
            var key = ConnectionKey.CreateContextScoped(snapshot, referrals, context);
            var lease = Pool.Acquire(key, () => LdapConnectionFactory.ConfigureOwned(
                LdapConnectionFactory.Create(snapshot), connection =>
                {
                    LdapConnectionFactory.ConfigureReferralChasing(connection, referrals);
                    connection.Bind();
                }), cancellationToken, reusable, preferFresh, minimumGeneration);
            return new ScopedSearchLease(lease, request, requestTimeout ?? snapshot.Timeout, authority);
        }, cancellationToken);
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
