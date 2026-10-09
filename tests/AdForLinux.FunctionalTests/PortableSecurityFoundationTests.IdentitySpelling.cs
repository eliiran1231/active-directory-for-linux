#pragma warning disable CA1416
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> ResolverUnsupportedSpellingCases()
    {
        var values = new List<string>
        {
            "Configuratiön", "Configuratio\u0308n", "Ｃｏｎｆｉｇｕｒａｔｉｏｎ", "Conﬁguration",
            "Configuraßion", "Con\u00adfiguration", "Con\u200bfiguration", "Con\ufefffiguration",
            "Configuration ", " Configuration", "App  Partition", "App Partition",
            "App-Partition", "App.Partition", "App_Partition", "App'Partition",
            "App\\,Partition", "App\\\\Partition", "App\\20Partition", "App+OU=Other"
        };
        foreach (var space in new[] { '\t', '\n', '\r', '\v', '\f', '\u0085', '\u00a0', '\u1680',
            '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007',
            '\u2008', '\u2009', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000' })
            values.Add("App" + space + "Partition");
        foreach (var value in values)
        foreach (var location in new[] { "entry", "result", "contexts", "domain", "configuration" })
        foreach (var mutation in new[] { false, true }) yield return [value, location, mutation];
    }

    [Theory]
    [MemberData(nameof(ResolverUnsupportedSpellingCases))]
    public void Resolver_spelling_contract_refuses_unverifiable_values_at_every_authority_input(string value, string location, bool mutation)
    {
        using var fixture = new IdentityFixture();
        const string domain = "DC=example,DC=com", config = "CN=Configuration,DC=example,DC=com";
        var suspect = "CN=" + value + "," + domain;
        fixture.MetadataResults = request => request.DistinguishedName == string.Empty
            ? [IdentityFixture.Row(("defaultNamingContext", [location == "domain" ? "DC=" + value + ",DC=com" : domain]),
                ("configurationNamingContext", [location == "configuration" ? suspect : config]),
                ("namingContexts", [domain, config, location == "contexts" ? suspect : "CN=AppPartition," + domain]),
                ("supportedControl", [AdIdentityLookup.DomainScopeControl]))] : null;
        if (location == "entry") fixture.Entry.Path = "LDAP://dc.example/CN=user," + suspect;
        if (location == "result") fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]),
            ("sAMAccountName", ["alice"]), ("objectClass", ["user"]), ("distinguishedName", ["CN=user," + suspect]))];
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); var resolver = fixture.Resolver; resolver.Bind(wrapper);
        var state = descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<NotSupportedException>(() =>
        {
            if (mutation) wrapper.SetOwner(new NTAccount("alice"));
            else resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount));
        });
        if (location != "result") Assert.DoesNotContain(fixture.Requests, r => r.Scope == System.DirectoryServices.Protocols.SearchScope.Subtree);
        Assert.Same(state, descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(0, descriptor.MutationVersion); Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Theory]
    [InlineData("cn=User01,ou=People42,dc=example,dc=com", false)]
    [InlineData("cn=User01,ou=People42,dc=example,dc=com", true)]
    [InlineData("DC=example,DC=com", false)]
    [InlineData("DC=example,DC=com", true)]
    public void Resolver_spelling_contract_preserves_supported_ascii_paths(string dn, bool mutation)
    {
        using var fixture = new IdentityFixture();
        fixture.Entry.Path = "LDAP://dc.example/" + dn;
        fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]),
            ("objectClass", ["user"]), ("distinguishedName", [dn]))];
        var resolver = fixture.Resolver;
        if (mutation)
        {
            var wrapper = new FacadeContracts.Wrapper(); resolver.Bind(wrapper);
            wrapper.SetOwner(new NTAccount("alice"));
            Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        }
        else Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Theory]
    [InlineData("entry", false)]
    [InlineData("entry", true)]
    [InlineData("result", false)]
    [InlineData("result", true)]
    public void Resolver_spelling_contract_recognizes_supported_application_boundary_case(string location, bool mutation)
        => Resolver_spelling_contract_refuses_unverifiable_values_at_every_authority_input("appPARTITION", location, mutation);

    [Fact]
    public void Resolver_spelling_contract_exhaustively_bounds_ascii_value_characters()
    {
        for (var code = 0; code < 128; code++)
        {
            using var fixture = new IdentityFixture();
            fixture.MetadataResults = request => request.DistinguishedName == string.Empty
                ? [IdentityFixture.Row(("defaultNamingContext", ["DC=example,DC=com"]),
                    ("configurationNamingContext", ["CN=Configuration,DC=example,DC=com"]),
                    ("namingContexts", ["DC=example,DC=com", "CN=Configuration,DC=example,DC=com", "CN=A" + (char)code + "B,DC=example,DC=com"]),
                    ("supportedControl", [AdIdentityLookup.DomainScopeControl]))] : null;
            var supported = code is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
            if (supported) Assert.Equal("EXAMPLE\\alice", fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
            else
            {
                Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
                Assert.DoesNotContain(fixture.Requests, r => r.Scope == System.DirectoryServices.Protocols.SearchScope.Subtree);
            }
        }
    }
}
