#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private const string PlanDomain = "DC=example,DC=com";
    private const string PlanConfig = "CN=Configuration,DC=example,DC=com";
    private static IdentitySearchRow PlanRoot() => IdentityFixture.Row(
        ("defaultNamingContext", [PlanDomain]), ("configurationNamingContext", [PlanConfig]),
        ("namingContexts", [PlanDomain, PlanConfig, "DC=foreign,DC=test", "CN=App," + PlanDomain]),
        ("supportedControl", [AdIdentityLookup.DomainScopeControl]));
    private static IdentitySearchRow PlanDomainRow() => IdentityFixture.Row(
        ("nCName", [PlanDomain]), ("nETBIOSName", ["EXAMPLE"]), ("dnsRoot", ["example.com"]), ("systemFlags", ["3"]));

    [Theory]
    [InlineData("sid", "objectSid", null)]
    [InlineData("alice", "sAMAccountName", "\\61\\6c\\69\\63\\65")]
    [InlineData("EXAMPLE\\alice", "sAMAccountName", "\\61\\6c\\69\\63\\65")]
    [InlineData("example.com\\alice", "sAMAccountName", "\\61\\6c\\69\\63\\65")]
    [InlineData("alice@other.test", "userPrincipalName", "\\61\\6c\\69\\63\\65\\40\\6f\\74\\68\\65\\72\\2e\\74\\65\\73\\74")]
    [InlineData("EXAMPLE\\alice@other.test", "sAMAccountName", "\\61\\6c\\69\\63\\65\\40\\6f\\74\\68\\65\\72\\2e\\74\\65\\73\\74")]
    [InlineData("EXAMPLE\\a*)(x=1)", "sAMAccountName", "\\61\\2a\\29\\28\\78\\3d\\31\\29")]
    [InlineData("é😀", "sAMAccountName", "\\c3\\a9\\f0\\9f\\98\\80")]
    public void Integrated_identity_plan_keeps_exact_single_domain_requests(string input, string attribute, string? escaped)
    {
        using var fixture = new IdentityFixture();
        fixture.MetadataResults = request => request.DistinguishedName == "" ? [PlanRoot()] : null;
        fixture.Entry.IdentitySessionFactory = options =>
        {
            Assert.Equal("dc.example", options.Host); Assert.Equal(389, options.Port);
            Assert.Equal(AuthType.Negotiate, options.AuthenticationType);
            return fixture.CreateSession();
        };
        IdentityReference identity = input == "sid" ? new SecurityIdentifier(U1, 0) : new NTAccount(input);
        _ = fixture.Resolver.Translate(identity, input == "sid" ? typeof(NTAccount) : typeof(SecurityIdentifier));
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
        Assert.Equal(6, fixture.Requests.Count);
        Assert.Equal("", fixture.Requests[0].DistinguishedName);
        Assert.Equal(ProtocolScope.Base, fixture.Requests[0].Scope);
        Assert.Equal(new[] { "defaultNamingContext", "configurationNamingContext", "namingContexts", "supportedControl" }, fixture.Requests[0].Attributes.Cast<string>());
        Assert.Equal("CN=Partitions," + PlanConfig, fixture.Requests[1].DistinguishedName);
        Assert.Equal(ProtocolScope.OneLevel, fixture.Requests[1].Scope);
        Assert.Equal(new[] { "nCName", "nETBIOSName", "dnsRoot", "systemFlags" }, fixture.Requests[1].Attributes.Cast<string>());
        Assert.Equal("(&(objectClass=crossRef)(nCName=\\44\\43\\3d\\65\\78\\61\\6d\\70\\6c\\65\\2c\\44\\43\\3d\\63\\6f\\6d))", fixture.Requests[1].Filter);
        var request = Assert.Single(fixture.AccountRequests);
        escaped ??= string.Concat(U1.Select(b => "\\" + b.ToString("x2")));
        Assert.Equal("(&(objectClass=*)(" + attribute + "=" + escaped + "))", request.Filter);
        Assert.Equal(new[] { "objectSid", "sAMAccountName", "objectClass", "distinguishedName" }, request.Attributes.Cast<string>());
        Assert.Equal(new[] { 2, 4, 5 }, fixture.Requests.Select((r, i) => (r, i)).Where(x => IdentityFixture.IsMembership(x.r)).Select(x => x.i));
        foreach (var scoped in fixture.Requests.Skip(2))
        {
            Assert.Equal(PlanDomain, scoped.DistinguishedName); Assert.Equal(ProtocolScope.Subtree, scoped.Scope);
            var control = Assert.Single(scoped.Controls.Cast<DirectoryControl>());
            Assert.Equal(AdIdentityLookup.DomainScopeControl, control.Type); Assert.True(control.IsCritical); Assert.True(control.ServerSide);
            Assert.Empty(control.GetValue()); Assert.Equal(2, scoped.SizeLimit);
        }
        Assert.All(fixture.Requests.Where(IdentityFixture.IsMembership), r => Assert.Equal(new[] { "1.1" }, r.Attributes.Cast<string>()));
        Assert.All(fixture.Requests.Take(2), r => Assert.Empty(r.Controls.Cast<DirectoryControl>()));
    }

    [Theory]
    [InlineData("FOREIGN\\alice")] [InlineData("foreign.test\\alice")]
    [InlineData("App\\alice")] [InlineData("Configuration\\alice")]
    [InlineData("EXAMPLE\\nested\\alice")]
    public void Discovered_other_contexts_never_authorize_a_qualified_account_plan(string name)
    {
        using var fixture = new IdentityFixture();
        fixture.MetadataResults = request => request.DistinguishedName == "" ? [PlanRoot()] : null;
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new NTAccount(name), typeof(SecurityIdentifier)));
        Assert.Empty(fixture.AccountRequests); Assert.Equal(3, fixture.Requests.Count);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
        Assert.Equal(PlanDomain, fixture.Requests[2].DistinguishedName);
    }

    [Theory]
    [InlineData("duplicate", false)] [InlineData("duplicate", true)]
    [InlineData("conflicting", false)] [InlineData("conflicting", true)]
    [InlineData("foreign", false)] [InlineData("foreign", true)]
    public void Domain_metadata_never_selects_first_match_from_multiple_rows(string kind, bool reverse)
    {
        using var fixture = new IdentityFixture();
        var other = kind switch
        {
            "foreign" => IdentityFixture.Row(("nCName", ["DC=foreign,DC=test"]), ("nETBIOSName", ["EXAMPLE"]), ("dnsRoot", ["example.com"]), ("systemFlags", ["3"])),
            "conflicting" => IdentityFixture.Row(("nCName", [PlanDomain]), ("nETBIOSName", ["OTHER"]), ("dnsRoot", ["other.test"]), ("systemFlags", ["3"])),
            _ => PlanDomainRow()
        };
        fixture.MetadataResults = request => request.DistinguishedName.StartsWith("CN=Partitions,")
            ? reverse ? [other, PlanDomainRow()] : [PlanDomainRow(), other] : null;
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new NTAccount("EXAMPLE\\alice"), typeof(SecurityIdentifier)));
        Assert.Equal(2, fixture.Requests.Count); Assert.Empty(fixture.AccountRequests);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Theory]
    [InlineData("root", "defaultNamingContext", "missing")]
    [InlineData("root", "configurationNamingContext", "missing")]
    [InlineData("root", "namingContexts", "missing")]
    [InlineData("root", "supportedControl", "missing")]
    [InlineData("root", "defaultNamingContext", "config")]
    [InlineData("root", "defaultNamingContext", "duplicate")]
    [InlineData("domain", "nCName", "foreign")]
    [InlineData("domain", "nCName", "duplicate")]
    [InlineData("domain", "nETBIOSName", "missing")]
    [InlineData("domain", "nETBIOSName", "empty")]
    [InlineData("domain", "nETBIOSName", "duplicate")]
    [InlineData("domain", "dnsRoot", "missing")]
    [InlineData("domain", "dnsRoot", "duplicate")]
    [InlineData("domain", "systemFlags", "missing")]
    [InlineData("domain", "systemFlags", "application")]
    public void Incomplete_or_non_domain_metadata_produces_no_executable_identity_plan(string phase, string attribute, string fault)
    {
        using var fixture = new IdentityFixture();
        var row = phase == "root" ? PlanRoot() : PlanDomainRow();
        var values = row.Attributes.ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
        switch (fault)
        {
            case "missing": values.Remove(attribute); break;
            case "empty": values[attribute] = [""]; break;
            case "duplicate": values[attribute] = [values[attribute][0], values[attribute][0]]; break;
            case "config": values[attribute] = [PlanConfig]; break;
            case "foreign": values[attribute] = ["DC=foreign,DC=test"]; break;
            default: values[attribute] = ["1"]; break;
        }
        fixture.MetadataResults = request => (phase == "root" ? request.DistinguishedName == "" : request.DistinguishedName.StartsWith("CN=Partitions,"))
            ? [new IdentitySearchRow(values)] : null;
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new NTAccount("alice"), typeof(SecurityIdentifier)));
        Assert.Equal(phase == "root" ? 1 : 2, fixture.Requests.Count);
        Assert.Empty(fixture.AccountRequests); Assert.DoesNotContain(fixture.Requests, IdentityFixture.IsMembership);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Fact]
    public void Identity_metadata_and_plans_are_immutable_data_without_session_or_authority()
    {
        var row = PlanDomainRow();
        var domain = AdIdentityDomainMetadata.ValidateDomain(PlanDomain, [row]);
        var plan = AdIdentityQueryPlan.Create(domain, new NTAccount("alice"));
        row.Attributes["nCName"][0] = "DC=foreign,DC=test";
        row.Attributes["nETBIOSName"][0] = "FOREIGN";
        var attributes = plan.GetAttributes(); attributes[0] = "userPassword";
        Assert.Equal(PlanDomain, domain.NamingContext); Assert.Equal("EXAMPLE", domain.NetbiosName);
        Assert.Equal(PlanDomain, plan.NamingContext); Assert.Equal("objectSid", plan.GetAttributes()[0]);
        foreach (var type in new[] { typeof(AdIdentityDomainMetadata), typeof(AdIdentityQueryPlan) })
        {
            Assert.All(type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public), field =>
            { Assert.True(field.IsInitOnly); Assert.Equal(typeof(string), field.FieldType); });
            Assert.All(type.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public), ctor => Assert.True(ctor.IsPrivate));
        }
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData(" ")]
    public void Identity_domain_metadata_cannot_construct_a_plan_without_a_naming_context(string? context)
    {
        var row = IdentityFixture.Row(("nCName", [context!]), ("nETBIOSName", ["EXAMPLE"]),
            ("dnsRoot", ["example.com"]), ("systemFlags", ["3"]));
        Assert.Throws<NotSupportedException>(() => AdIdentityDomainMetadata.ValidateDomain(context!, [row]));
    }
}
