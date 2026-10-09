#pragma warning disable CA1416
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> ResolverScopeCases()
    {
        foreach (var mutation in new[] { false, true })
            foreach (var scenario in new[] { "gc", "gc-tls", "entry-child", "entry-child-unlisted", "entry-app", "entry-app-cn", "entry-config", "entry-other",
                "row-child", "row-child-unlisted", "row-app", "row-app-cn", "row-config", "row-other", "row-missing-dn", "row-escaped-suffix",
                "missing-contexts", "missing-control", "application-default" }) yield return [scenario, mutation];
    }

    [Theory]
    [MemberData(nameof(ResolverScopeCases))]
    public void Resolver_scope_boundaries_refuse_before_emitting_names_or_mutating(string scenario, bool mutation)
    {
        using var fixture = new IdentityFixture();
        var path = scenario switch
        {
            "gc" => "LDAP://dc.example:3268/DC=example,DC=com",
            "gc-tls" => "LDAP://dc.example:3269/DC=example,DC=com",
            "entry-child" or "entry-child-unlisted" => "LDAP://dc.example/CN=user,DC=child,DC=example,DC=com",
            "entry-app" => "LDAP://dc.example/CN=user,DC=App,DC=example,DC=com",
            "entry-app-cn" => "LDAP://dc.example/CN=user,CN=App,DC=example,DC=com",
            "entry-config" => "LDAP://dc.example/CN=user,CN=Configuration,DC=example,DC=com",
            "entry-other" => "LDAP://dc.example/CN=user,DC=other,DC=com",
            _ => null
        };
        if (path is not null) fixture.Entry.Path = path;
        fixture.MetadataResults = request =>
        {
            if (request.DistinguishedName == string.Empty)
            {
                var fields = new List<(string, object[])>
                {
                    ("defaultNamingContext", ["DC=example,DC=com"]),
                    ("configurationNamingContext", ["CN=Configuration,DC=example,DC=com"])
                };
                if (scenario != "missing-contexts") fields.Add(("namingContexts", scenario.EndsWith("-unlisted")
                    ? ["DC=example,DC=com", "CN=Configuration,DC=example,DC=com"]
                    : ["DC=example,DC=com", "DC=child,DC=example,DC=com", "DC=App,DC=example,DC=com", "CN=App,DC=example,DC=com", "CN=Configuration,DC=example,DC=com"]));
                if (scenario != "missing-control") fields.Add(("supportedControl", ["1.2.840.113556.1.4.1339"]));
                return [IdentityFixture.Row(fields.ToArray())];
            }
            if (scenario == "application-default" && request.DistinguishedName.StartsWith("CN=Partitions,"))
                return [IdentityFixture.Row(("nCName", ["DC=example,DC=com"]), ("nETBIOSName", ["EXAMPLE"]), ("dnsRoot", ["example.com"]), ("systemFlags", ["1"]))];
            return null;
        };
        if (scenario.StartsWith("row-")) fixture.Results = _ =>
        {
            var fields = new List<(string, object[])> { ("objectSid", [U1]), ("sAMAccountName", ["child-user"]), ("objectClass", ["user"]) };
            var dn = scenario switch
            {
                "row-child" or "row-child-unlisted" => "CN=user,DC=child,DC=example,DC=com",
                "row-app" => "CN=user,DC=App,DC=example,DC=com",
                "row-app-cn" => "CN=user,CN=App,DC=example,DC=com",
                "row-config" => "CN=user,CN=Configuration,DC=example,DC=com",
                "row-other" => "CN=user,DC=other,DC=com",
                "row-escaped-suffix" => "CN=user\\,DC=example,DC=com",
                _ => null
            };
            if (dn is not null) fields.Add(("distinguishedName", [dn]));
            return [IdentityFixture.Row(fields.ToArray())];
        };
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); var resolver = fixture.Resolver; resolver.Bind(wrapper);
        var state = descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<NotSupportedException>(() =>
        {
            if (mutation) wrapper.SetOwner(new NTAccount("bare-name"));
            else resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount));
        });
        Assert.Same(state, descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(0, descriptor.MutationVersion); Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        if (scenario is "gc" or "gc-tls") Assert.Equal(0, fixture.Opened);
        if (scenario.StartsWith("entry-") || scenario is "missing-contexts" or "missing-control" or "application-default")
            Assert.DoesNotContain(fixture.Requests, r => r.Scope == System.DirectoryServices.Protocols.SearchScope.Subtree);
    }

    [Theory]
    [InlineData("CN=alice,DC=example,DC=com")]
    [InlineData("CN=last\\, first,OU=People,DC=example,DC=com")]
    [InlineData("CN=backslash\\\\,OU=People,DC=example,DC=com")]
    [InlineData("DC=example,DC=com")]
    public void Resolver_scope_accepts_verified_domain_rdns_and_requires_critical_single_nc_search(string dn)
    {
        using var fixture = new IdentityFixture();
        fixture.Entry.Path = "LDAP://dc.example/" + dn;
        fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]),
            ("objectClass", ["user"]), ("distinguishedName", [dn]))];
        Assert.Equal("EXAMPLE\\alice", fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        var request = fixture.Requests.Last();
        var control = Assert.Single(request.Controls.Cast<System.DirectoryServices.Protocols.DirectoryControl>());
        Assert.Equal(AdIdentityLookup.DomainScopeControl, control.Type);
        Assert.True(control.IsCritical); Assert.True(control.ServerSide); Assert.Empty(control.GetValue());
        Assert.Contains("distinguishedName", request.Attributes.Cast<string>());
    }
    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(false, 3)]
    [InlineData(false, 4)]
    [InlineData(false, 5)]
    [InlineData(false, 6)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    [InlineData(true, 3)]
    [InlineData(true, 4)]
    [InlineData(true, 5)]
    [InlineData(true, 6)]
    public void Unread_typed_rule_sections_refuse_before_identity_io(bool audit, int route)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4), Acl(4)), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        wrapper.SetRawReadContext(SecurityMasks.Owner, fixture.Resolver);
        fixture.Resolver.Bind(wrapper);
        var state = descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<InvalidOperationException>(() =>
        {
            if (audit) wrapper.AuditRoute(route, new FacadeContracts.UR(new NTAccount("alice"), 16, false, 0, 0,
                System.Security.AccessControl.AuditFlags.Success, Guid.Empty, Guid.Empty));
            else wrapper.AccessRoute(route, new FacadeContracts.AR(new NTAccount("alice"), 16, false, 0, 0,
                System.Security.AccessControl.AccessControlType.Allow, Guid.Empty, Guid.Empty));
        });
        Assert.Equal(0, fixture.Opened); Assert.Empty(fixture.Requests);
        Assert.Same(state, descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(0, descriptor.MutationVersion); Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    private sealed class LifetimeConnection : IDisposable
    {
        internal int DisposeCalls;
        public void Dispose() => DisposeCalls++;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Ldap_factory_disposes_setup_failures_and_preserves_exception(bool lateFailure)
    {
        var allocated = new LifetimeConnection();
        var expected = new InvalidOperationException("controlled setup failure");
        var completedSteps = 0;
        var exception = Record.Exception(() => LdapConnectionFactory.ConfigureOwned(allocated, connection =>
        {
            Assert.Same(allocated, connection);
            if (lateFailure) completedSteps = 5;
            throw expected;
        }));
        Assert.Same(expected, exception); Assert.Equal(1, allocated.DisposeCalls);
        Assert.Equal(lateFailure ? 5 : 0, completedSteps);
    }

    [Fact]
    public void Ldap_factory_transfers_successful_connection_ownership_to_caller()
    {
        var allocated = new LifetimeConnection();
        var connection = LdapConnectionFactory.ConfigureOwned(allocated, value => Assert.Same(allocated, value));
        Assert.Same(allocated, connection); Assert.Equal(0, allocated.DisposeCalls);
        connection.Dispose(); Assert.Equal(1, allocated.DisposeCalls);
    }
}
