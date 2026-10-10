namespace AdForLinux.DirectoryServices.Ldap;

// Validated server metadata is data, not permission to connect to or search a domain.
// AdIdentityLookup still proves membership on its existing checked session.
internal sealed class AdIdentityDomainMetadata
{
    internal string NamingContext { get; }
    internal string NetbiosName { get; }
    internal string DnsName { get; }

    private AdIdentityDomainMetadata(string namingContext, string netbiosName, string dnsName)
    { NamingContext = namingContext; NetbiosName = netbiosName; DnsName = dnsName; }

    internal static (string Domain, string Configuration) ValidateRoot(IReadOnlyList<IdentitySearchRow> rows)
    {
        var root = Unique(rows);
        var domain = root.Text("defaultNamingContext"); var config = root.Text("configurationNamingContext");
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(config))
            throw new NotSupportedException("Domain scope metadata is unavailable.");
        var contexts = root.Values("namingContexts");
        if (contexts.Length == 0 || contexts.Any(v => v is not string text || string.IsNullOrWhiteSpace(text))
            || !root.Values("supportedControl").Contains(AdIdentityLookup.DomainScopeControl))
            throw new NotSupportedException("Complete naming-context metadata and critical domain-scope control support are required.");
        var namingContexts = contexts.Cast<string>().ToArray();
        if (!namingContexts.Contains(domain, StringComparer.OrdinalIgnoreCase)
            || !namingContexts.Contains(config, StringComparer.OrdinalIgnoreCase)
            || string.Equals(domain, config, StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("The default domain naming context is ambiguous.");
        return (domain, config);
    }

    internal static AdIdentityDomainMetadata ValidateDomain(string expectedDomain, IReadOnlyList<IdentitySearchRow> rows)
    {
        var crossRef = Unique(rows);
        if (string.IsNullOrWhiteSpace(expectedDomain)
            || !int.TryParse(crossRef.Text("systemFlags"), out var flags) || (flags & 2) == 0
            || !string.Equals(crossRef.Text("nCName"), expectedDomain, StringComparison.OrdinalIgnoreCase)
            || crossRef.Text("nETBIOSName") is not { Length: > 0 } netbios
            || crossRef.Text("dnsRoot") is not { Length: > 0 } dns)
            throw new NotSupportedException("Unambiguous domain qualification metadata is unavailable.");
        return new(expectedDomain, netbios, dns);
    }

    private static IdentitySearchRow Unique(IReadOnlyList<IdentitySearchRow> rows) => rows.Count == 1 ? rows[0]
        : throw new NotSupportedException("Unambiguous domain scope metadata is unavailable.");
}
