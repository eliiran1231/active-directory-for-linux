using System.Diagnostics;
using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using AdForLinux.Security.Principal;

namespace AdForLinux.DirectoryServices.Ldap;

internal sealed record IdentitySearchRow(IReadOnlyDictionary<string, object[]> Attributes, string? DistinguishedName = null)
{
    internal string? Text(string key) => Attributes.TryGetValue(key, out var values) && values.Length == 1
        ? values[0] as string : null;
    internal object[] Values(string key) => Attributes.TryGetValue(key, out var values) ? values : [];
}
internal interface IIdentitySearchSession : IDisposable
{
    IReadOnlyList<IdentitySearchRow> Search(SearchRequest request, TimeSpan remaining);
}
internal sealed class LdapIdentitySearchSession : IIdentitySearchSession
{
    private readonly LdapConnection connection;
    internal LdapIdentitySearchSession(LdapConnectionOptions options)
    {
        connection = LdapConnectionFactory.Create(options);
        try
        {
            LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.None);
            connection.Bind();
        }
        catch { connection.Dispose(); throw; }
    }
    public IReadOnlyList<IdentitySearchRow> Search(SearchRequest request, TimeSpan remaining)
    {
        var response = (SearchResponse)LdapExceptionTranslator.Execute(() => connection.SendRequest(request, remaining));
        RequireCompleteResult(response.ResultCode, response.References.Count);
        var result = new List<IdentitySearchRow>();
        foreach (SearchResultEntry row in response.Entries)
        {
            var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in row.Attributes.AttributeNames)
            {
                var attribute = row.Attributes[name];
                values[name] = name.Equals("objectSid", StringComparison.OrdinalIgnoreCase)
                    ? attribute.GetValues(typeof(byte[])) : attribute.GetValues(typeof(string));
            }
            result.Add(new(values, row.DistinguishedName));
        }
        return result;
    }
    internal static void RequireCompleteResult(ResultCode resultCode, int referenceCount)
    {
        if (resultCode != ResultCode.Success || referenceCount != 0)
            throw new NotSupportedException("Identity lookup did not return a complete result within the authorized domain.");
    }
    public void Dispose() => connection.Dispose();
}

// AD domain lookup, not Windows LSA/trust traversal. No guessed server, domain label,
// foreign-principal CN, referral follow-up, or fallback credential is used.
internal sealed class AdIdentityLookup(IIdentitySearchSession session, TimeSpan timeout, Action validate, string? entryTarget, bool useVerifiedDomainRoot = false)
{
    internal const string DomainScopeControl = "1.2.840.113556.1.4.1339";
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private AdIdentityDomainMetadata? scope;
    private string? verifiedEntryTarget;
    internal IdentityReference? Translate(IdentityReference identity)
    {
        var domain = scope ??= Discover();
        var plan = AdIdentityQueryPlan.Create(domain, identity);
        var rows = Search(plan.NamingContext, plan.Filter, plan.Scope, plan.GetAttributes());
        if (rows.Count == 0) return null;
        if (rows.Count != 1) throw new InvalidOperationException("Identity lookup is ambiguous within the authorized domain.");
        var row = rows[0];
        RequireDomainMember(row.DistinguishedName, domain.NamingContext);
        if (row.Values("objectClass").OfType<string>().Any(c => c.Equals("foreignSecurityPrincipal", StringComparison.OrdinalIgnoreCase)))
            throw new NotSupportedException("Foreign security principals require an explicitly authorized issuing-domain context.");
        if (row.Values("objectSid") is not [byte[] binary] || row.Text("sAMAccountName") is not { Length: > 0 } sam) return null;
        var resolvedSid = new SecurityIdentifier(binary, 0);
        if (binary.Length != resolvedSid.BinaryLength) throw new InvalidOperationException("Identity lookup returned an invalid SID encoding.");
        if (identity is SecurityIdentifier input && !input.Equals(resolvedSid)) throw new InvalidOperationException("Identity lookup returned a different SID.");
        return identity is SecurityIdentifier ? new NTAccount(domain.NetbiosName, sam) : resolvedSid;
    }
    private AdIdentityDomainMetadata Discover()
    {
        var root = AdIdentityDomainMetadata.ValidateRoot(Search(string.Empty, "(objectClass=*)", ProtocolScope.Base,
            "defaultNamingContext", "configurationNamingContext", "namingContexts", "supportedControl"));
        var domain = AdIdentityDomainMetadata.ValidateDomain(root.Domain,
            Search("CN=Partitions," + root.Configuration, "(&(objectClass=crossRef)(nCName=" + EscapeText(root.Domain) + "))",
                ProtocolScope.OneLevel, "nCName", "nETBIOSName", "dnsRoot", "systemFlags"));
        var target = entryTarget ?? (useVerifiedDomainRoot ? domain.NamingContext : null);
        RequireDomainMember(target, domain.NamingContext);
        verifiedEntryTarget = target;
        return domain;
    }
    internal void Complete()
    {
        // Recheck current membership after all mappings. This is not a directory
        // transaction or an object-identity pin across deletion/recreation.
        if (scope is { } verified) RequireDomainMember(verifiedEntryTarget, verified.NamingContext);
    }

    private void RequireDomainMember(string? distinguishedName, string domain)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
            throw new NotSupportedException("A nonempty DN is required to verify domain membership.");
        // The base is independently verified metadata, NEVER the candidate DN.
        // AD evaluates DN equality. The critical control restricts this search to
        // that base's NC; a complete unique response is the scope proof. Request
        // no attributes: scope proof introduces no GUID/SID read-permission gate.
        var rows = Search(domain, "(distinguishedName=" + EscapeText(distinguishedName) + ")",
            ProtocolScope.Subtree, "1.1");
        if (rows.Count != 1 || string.IsNullOrWhiteSpace(rows[0].DistinguishedName))
            throw new NotSupportedException("The entry's membership in the verified domain could not be established.");
    }

    private IReadOnlyList<IdentitySearchRow> Search(string dn, string filter, ProtocolScope scope, params string[] attributes)
    {
        validate();
        var remaining = timeout - elapsed.Elapsed;
        if (remaining <= TimeSpan.Zero) throw new TimeoutException("The identity resolution deadline expired.");
        var request = new SearchRequest(dn, filter, scope, attributes) { SizeLimit = 2, TimeLimit = remaining };
        if (scope == ProtocolScope.Subtree)
            request.Controls.Add(new DirectoryControl(DomainScopeControl, null, true, true));
        var result = session.Search(request, remaining);
        validate();
        if (elapsed.Elapsed >= timeout) throw new TimeoutException("The identity resolution deadline expired.");
        return result;
    }
    internal static string EscapeText(string value) => AdIdentityQueryPlan.EscapeText(value);
}
