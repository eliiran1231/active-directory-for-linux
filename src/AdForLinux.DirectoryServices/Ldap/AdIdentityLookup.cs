using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Text;
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
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private (string Domain, string Netbios, string Dns)? scope;
    private string? verifiedEntryTarget;
    internal IdentityReference? Translate(IdentityReference identity)
    {
        var domain = scope ??= Discover();
        string assertion;
        if (identity is SecurityIdentifier sid)
        {
            var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            assertion = "(objectSid=" + Escape(bytes) + ")";
        }
        else
        {
            var name = identity.Value;
            var slash = name.IndexOf('\\');
            if (slash >= 0)
            {
                var qualifier = name[..slash]; name = name[(slash + 1)..];
                if (name.Contains('\\') || name.Length == 0 ||
                    (!qualifier.Equals(domain.Netbios, StringComparison.OrdinalIgnoreCase) && !qualifier.Equals(domain.Dns, StringComparison.OrdinalIgnoreCase)))
                    throw new NotSupportedException("The account qualifier is outside the verified domain scope.");
                assertion = "(sAMAccountName=" + EscapeText(name) + ")";
            }
            else assertion = "(" + (name.Contains('@') ? "userPrincipalName" : "sAMAccountName") + "=" + EscapeText(name) + ")";
        }
        var rows = Search(domain.Domain, "(&(objectClass=*)(" + assertion[1..^1] + "))", ProtocolScope.Subtree,
            "objectSid", "sAMAccountName", "objectClass", "distinguishedName");
        if (rows.Count == 0) return null;
        if (rows.Count != 1) throw new InvalidOperationException("Identity lookup is ambiguous within the authorized domain.");
        var row = rows[0];
        RequireDomainMember(row.DistinguishedName, domain.Domain);
        if (row.Values("objectClass").OfType<string>().Any(c => c.Equals("foreignSecurityPrincipal", StringComparison.OrdinalIgnoreCase)))
            throw new NotSupportedException("Foreign security principals require an explicitly authorized issuing-domain context.");
        if (row.Values("objectSid") is not [byte[] binary] || row.Text("sAMAccountName") is not { Length: > 0 } sam) return null;
        var resolvedSid = new SecurityIdentifier(binary, 0);
        if (binary.Length != resolvedSid.BinaryLength) throw new InvalidOperationException("Identity lookup returned an invalid SID encoding.");
        if (identity is SecurityIdentifier input && !input.Equals(resolvedSid)) throw new InvalidOperationException("Identity lookup returned a different SID.");
        return identity is SecurityIdentifier ? new NTAccount(domain.Netbios, sam) : resolvedSid;
    }
    private (string, string, string) Discover()
    {
        var root = Unique(Search(string.Empty, "(objectClass=*)", ProtocolScope.Base,
            "defaultNamingContext", "configurationNamingContext", "namingContexts", "supportedControl"));
        var domain = root.Text("defaultNamingContext"); var config = root.Text("configurationNamingContext");
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(config)) throw new NotSupportedException("Domain scope metadata is unavailable.");
        var contexts = root.Values("namingContexts");
        if (contexts.Length == 0 || contexts.Any(v => v is not string text || string.IsNullOrWhiteSpace(text))
            || !root.Values("supportedControl").Contains(DomainScopeControl))
            throw new NotSupportedException("Complete naming-context metadata and critical domain-scope control support are required.");
        var namingContexts = contexts.Cast<string>().ToArray();
        if (!namingContexts.Contains(domain, StringComparer.OrdinalIgnoreCase)
            || !namingContexts.Contains(config, StringComparer.OrdinalIgnoreCase)
            || string.Equals(domain, config, StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("The default domain naming context is ambiguous.");
        var crossRef = Unique(Search("CN=Partitions," + config, "(&(objectClass=crossRef)(nCName=" + EscapeText(domain) + "))",
            ProtocolScope.OneLevel, "nCName", "nETBIOSName", "dnsRoot", "systemFlags"));
        if (!int.TryParse(crossRef.Text("systemFlags"), out var flags) || (flags & 2) == 0
            || !string.Equals(crossRef.Text("nCName"), domain, StringComparison.OrdinalIgnoreCase)
            || crossRef.Text("nETBIOSName") is not { Length: > 0 } netbios || crossRef.Text("dnsRoot") is not { Length: > 0 } dns)
            throw new NotSupportedException("Unambiguous domain qualification metadata is unavailable.");
        var target = entryTarget ?? (useVerifiedDomainRoot ? domain : null);
        RequireDomainMember(target, domain);
        verifiedEntryTarget = target;
        return (domain, netbios, dns);
    }
    internal void Complete()
    {
        // Recheck current membership after all mappings. This is not a directory
        // transaction or an object-identity pin across deletion/recreation.
        if (scope is { } verified) RequireDomainMember(verifiedEntryTarget, verified.Domain);
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
    private static IdentitySearchRow Unique(IReadOnlyList<IdentitySearchRow> rows) => rows.Count == 1 ? rows[0]
        : throw new NotSupportedException("Unambiguous domain scope metadata is unavailable.");
    internal static string EscapeText(string value) => Escape(Utf8.GetBytes(value));
    private static string Escape(byte[] bytes) => string.Concat(bytes.Select(b => "\\" + b.ToString("x2")));
}
