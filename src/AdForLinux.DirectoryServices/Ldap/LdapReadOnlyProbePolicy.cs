using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using System.DirectoryServices.Protocols;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace AdForLinux.DirectoryServices.Ldap;

// Internal diagnostic authority, never enabled by environment or ordinary public
// constructors. A separate probe process is required; this is not a general API.
internal sealed class LdapReadOnlyProbePolicy
{
    private static readonly ConditionalWeakTable<LdapConnection, LdapReadOnlyProbePolicy> Connections = new();
    private readonly TimeProvider clock;
    private readonly long started;
    private int failed;
    internal string Host { get; }
    internal string FixtureDn { get; }
    internal string SchemaDn { get; }
    internal Guid Id { get; } = Guid.NewGuid();

    internal LdapReadOnlyProbePolicy(string host, string fixtureDn, string schemaDn, TimeProvider? timeProvider = null)
    {
        if (Uri.CheckHostName(host) != UriHostNameType.Dns || host.Contains(':') || host.EndsWith('.') || !host.Contains('.')
            || host.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-'))
            || !ValidDn(fixtureDn) || !ValidDn(schemaDn)
            || string.Equals(fixtureDn, schemaDn, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid explicit probe scope.");
        Host = host; FixtureDn = fixtureDn; SchemaDn = schemaDn;
        clock = timeProvider ?? TimeProvider.System; started = clock.GetTimestamp();
    }

    private static bool ValidDn(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Contains('=') && !value.Any(char.IsControl) && !value.Contains('/') && !value.Contains('<');
    internal void Refuse() { Interlocked.Exchange(ref failed, 1); throw new ProbePolicyException(); }
    internal void Check()
    {
        if (Volatile.Read(ref failed) != 0 || clock.GetElapsedTime(started) >= TimeSpan.FromSeconds(60)) Refuse();
    }
    internal TimeSpan Remaining()
    {
        Check();
        return TimeSpan.FromTicks(Math.Min(TimeSpan.FromSeconds(10).Ticks,
            (TimeSpan.FromSeconds(60) - clock.GetElapsedTime(started)).Ticks));
    }
    internal void ValidateAdmission(LdapConnectionOptions options, ReferralChasingOption referrals)
    {
        Check();
        if (!ReferenceEquals(options.ReadOnlyProbe, this) || !string.Equals(options.Host, Host, StringComparison.OrdinalIgnoreCase)
            || options.Port != 636 || !options.UseSsl || options.UseStartTls || options.SkipCertificateCheck
            || options.AuthenticationType != AuthType.Basic || options.Signing || options.Sealing
            || options.RestrictedKerberos is not null || options.IsAnonymous
            || string.IsNullOrWhiteSpace(options.BindPassword) || referrals != ReferralChasingOption.None
            || options.Timeout <= TimeSpan.Zero || options.Timeout > TimeSpan.FromSeconds(10)) Refuse();
    }
    internal void ValidatePath(LdapPath path)
    {
        Check();
        if (!string.Equals(path.Host, Host, StringComparison.OrdinalIgnoreCase) || path.Port != 636
            || !(path.DistinguishedName.Length == 0 || Same(path.DistinguishedName, FixtureDn) || Same(path.DistinguishedName, SchemaDn))) Refuse();
    }
    internal void ValidateRequest(DirectoryRequest request)
    {
        Check();
        if (request is not SearchRequest search) { Refuse(); return; }
        if (search.Aliases != System.DirectoryServices.Protocols.DereferenceAlias.Never) Refuse();
        var dn = search.DistinguishedName;
        if (!(dn.Length == 0 && search.Scope == ProtocolScope.Base
            || Same(dn, FixtureDn) && search.Scope == ProtocolScope.Base
            || Same(dn, SchemaDn) && search.Scope == ProtocolScope.OneLevel)) Refuse();
        if (dn.Length == 0 && (search.Filter as string != "(objectClass=*)"
            || !search.Attributes.Cast<string>().SequenceEqual(new[] { "schemaNamingContext" }))) Refuse();
        foreach (DirectoryControl control in search.Controls)
        {
            if (control is not SecurityDescriptorFlagControl security
                || (security.SecurityMasks & ~System.DirectoryServices.Protocols.SecurityMasks.Owner
                    & ~System.DirectoryServices.Protocols.SecurityMasks.Group
                    & ~System.DirectoryServices.Protocols.SecurityMasks.Dacl) != 0) Refuse();
        }
        // Base reads return at most one fixture/root row. Schema reads are
        // restricted to the supplied schema container, with a finite row cap.
        var maximum = Same(dn, SchemaDn) ? 256 : 2;
        if (search.SizeLimit == 0) search.SizeLimit = maximum;
        if (search.SizeLimit > maximum || search.SizeLimit < 0) Refuse();
        var budget = Remaining();
        if (search.TimeLimit == TimeSpan.Zero || search.TimeLimit > budget) search.TimeLimit = budget;
        if (Same(dn, SchemaDn)) _ = SchemaNames(search);
    }
    internal void ValidateResponse(SearchRequest request, DirectoryResponse response)
    {
        Check();
        if (response is not SearchResponse search || response.ResultCode != ResultCode.Success
            || response.Referral.Length != 0 || search.References.Count != 0 || response.Controls.Length != 0) { Refuse(); return; }
        if (search.Entries.Count == 0 || search.Entries.Count > (Same(request.DistinguishedName, SchemaDn) ? 256 : 1)) Refuse();
        var expected = Same(request.DistinguishedName, SchemaDn) ? SchemaNames(request) : null;
        var returned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (SearchResultEntry row in search.Entries)
        {
            if (row.Controls.Length != 0 || (expected is not null
                ? !Same(LdapDistinguishedName.Parent(row.DistinguishedName) ?? "", SchemaDn)
                : !Same(row.DistinguishedName, request.DistinguishedName))) Refuse();
            if (expected is not null)
            {
                var name = OneString(row, "lDAPDisplayName");
                var syntax = OneString(row, "attributeSyntax");
                var om = OneString(row, "oMSyntax");
                if (!expected.Contains(name, StringComparer.OrdinalIgnoreCase) || !returned.Add(name)
                    || !syntax.StartsWith("2.5.5.", StringComparison.Ordinal)
                    || !int.TryParse(syntax[6..], out var kind) || kind is < 1 or > 17
                    || syntax != "2.5.5." + kind.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    || !int.TryParse(om, out var code) || code is < 1 or > 127
                    || om != code.ToString(System.Globalization.CultureInfo.InvariantCulture)) Refuse();
            }
        }
        if (expected is not null && returned.Count != expected.Length) Refuse();
        if (request.DistinguishedName.Length == 0 && search.Entries.Count == 1)
        {
            if (request.Attributes.Contains("schemaNamingContext") && !Same(OneString(search.Entries[0], "schemaNamingContext"), SchemaDn)) Refuse();
        }
    }
    private string OneString(SearchResultEntry row, string name)
    {
        if (row.Attributes[name] is not { Count: 1 } attribute) { Refuse(); return ""; }
        var values = attribute.GetValues(typeof(string));
        if (values is not [string]) { Refuse(); return ""; }
        return (string)values[0];
    }
    private string[] SchemaNames(SearchRequest request)
    {
        var filter = request.Filter as string ?? "";
        var names = Regex.Matches(filter, @"\(lDAPDisplayName=([A-Za-z0-9-]+)\)")
            .Select(match => match.Groups[1].Value).ToArray();
        var body = names.Length == 1 ? "(lDAPDisplayName=" + names[0] + ")"
            : "(|" + string.Concat(names.Select(name => "(lDAPDisplayName=" + name + ")")) + ")";
        if (names.Length == 0 || names.Length > 256 || names.Distinct(StringComparer.OrdinalIgnoreCase).Count() != names.Length
            || filter != "(&(objectClass=attributeSchema)" + body + ")"
            || !request.Attributes.Cast<string>().SequenceEqual(new[] { "lDAPDisplayName", "attributeSyntax", "oMSyntax" })) Refuse();
        return names;
    }
    private static bool Same(string first, string second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    internal void Register(LdapConnection connection) { Check(); Connections.Add(connection, this); }
    internal static LdapReadOnlyProbePolicy? For(LdapConnection connection) => Connections.TryGetValue(connection, out var policy) ? policy : null;
    internal T Execute<T>(DirectoryRequest request, Func<TimeSpan, T> send) where T : DirectoryResponse
    {
        try
        {
            ValidateRequest(request);
            var response = send(Remaining());
            ValidateResponse((SearchRequest)request, response);
            return response;
        }
        catch { Interlocked.Exchange(ref failed, 1); throw new ProbePolicyException(); }
    }
    internal sealed class ProbePolicyException : InvalidOperationException
    {
        internal ProbePolicyException() : base("Read-only probe policy refused the operation.") { }
    }
}
