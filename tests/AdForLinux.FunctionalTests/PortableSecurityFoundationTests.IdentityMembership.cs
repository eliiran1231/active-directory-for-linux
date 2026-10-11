#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> ServerVerifiedDnCases()
    {
        foreach (var mutation in new[] { false, true })
        foreach (var dn in new[] { "CN=ordinary user,OU=People,DC=example,DC=com",
            "CN=Jörg,OU=Research and Development,DC=example,DC=com", "CN=Jose\u0301,DC=example,DC=com",
            "CN=ａｌｉｃｅ,DC=example,DC=com", "CN=last\\, first,DC=example,DC=com",
            "CN=backslash\\\\,DC=example,DC=com", "CN=ali\\63e,DC=example,DC=com",
            "2.5.4.3=alice,0.9.2342.19200300.100.1.25=example,DC=com",
            "CN=App-Partition,OU=NotAnNC,DC=example,DC=com", "CN=a*)(objectClass=*),DC=example,DC=com" })
            yield return [dn, mutation];
    }

    [Theory]
    [MemberData(nameof(ServerVerifiedDnCases))]
    public void Server_membership_accepts_declared_success_without_client_dn_equivalence(string dn, bool mutation)
    {
        using var fixture = new IdentityFixture(); fixture.Entry.Path = "LDAP://dc.example/" + dn;
        // A scripted server result, not a local emulator or recording of AD matching.
        // Its returned spelling deliberately differs; no attribute permissions assumed.
        fixture.MembershipResults = _ => [new IdentitySearchRow(new Dictionary<string, object[]>(), "CN=canonical,DC=example,DC=com")];
        fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]),
            ("objectClass", ["user"]), ("distinguishedName", [dn]))];
        var wrapper = new FacadeContracts.Wrapper(); var resolver = fixture.Resolver; resolver.Bind(wrapper);
        if (mutation) { wrapper.SetOwner(new NTAccount("alice")); Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier))); }
        else Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        var proof = fixture.Requests.Where(IdentityFixture.IsMembership).ToArray();
        Assert.Equal(3, proof.Length); Assert.Single(fixture.AccountRequests);
        foreach (var request in proof)
        {
            Assert.Equal("DC=example,DC=com", request.DistinguishedName); // never candidate-rooted
            Assert.Equal(SearchScope.Subtree, request.Scope);
            Assert.Equal("(distinguishedName=" + AdIdentityLookup.EscapeText(dn) + ")", request.Filter);
            Assert.Equal(new[] { "1.1" }, request.Attributes.Cast<string>());
            Assert.Equal(2, request.SizeLimit); Assert.True(request.TimeLimit > TimeSpan.Zero);
        }
        foreach (var request in fixture.Requests.Where(r => r.Scope == SearchScope.Subtree))
        {
            var control = Assert.Single(request.Controls.Cast<DirectoryControl>());
            Assert.Equal(AdIdentityLookup.DomainScopeControl, control.Type);
            Assert.True(control.IsCritical); Assert.True(control.ServerSide); Assert.Empty(control.GetValue());
        }
        var limits = fixture.Requests.Select(r => r.TimeLimit).ToArray();
        Assert.All(limits.Zip(limits.Skip(1)), pair => Assert.True(pair.First >= pair.Second));
        Assert.True(fixture.Requests.IndexOf(proof[0]) < fixture.Requests.IndexOf(fixture.AccountRequests.Single()));
        Assert.Same(proof[^1], fixture.Requests.Last());
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Server_membership_supports_hyphenated_domain_and_unrelated_unicode_nc(bool mutation)
    {
        using var fixture = new IdentityFixture();
        const string domain = "DC=example-domain,DC=com", config = "CN=Configuration,DC=example-domain,DC=com";
        fixture.Entry.Path = "LDAP://dc.example/CN=ordinary user," + domain;
        fixture.MetadataResults = request => request.DistinguishedName == string.Empty
            ? [IdentityFixture.Row(("defaultNamingContext", [domain]), ("configurationNamingContext", [config]),
                ("namingContexts", [domain, config, "CN=App Pärtition," + domain]), ("supportedControl", [AdIdentityLookup.DomainScopeControl]))]
            : request.Scope == SearchScope.OneLevel
                ? [IdentityFixture.Row(("nCName", [domain]), ("nETBIOSName", ["EXAMPLE"]), ("dnsRoot", ["example-domain.com"]), ("systemFlags", ["3"]))] : null;
        fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]),
            ("objectClass", ["user"]), ("distinguishedName", ["CN=ordinary user," + domain]))];
        var resolver = fixture.Resolver;
        if (mutation) Assert.Equal(new SecurityIdentifier(U1, 0), resolver.Translate(new NTAccount("alice"), typeof(SecurityIdentifier)));
        else Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        Assert.All(fixture.Requests.Where(r => r.Scope == SearchScope.Subtree), r => Assert.Equal(domain, r.DistinguishedName));
    }

    public static IEnumerable<object[]> MembershipFailureCases()
    {
        foreach (var phase in new[] { 1, 2, 3 })
        foreach (var failure in new[] { "absent", "ambiguous", "missing-dn", "denied", "timeout", "referral", "partial", "unsupported-control" })
            yield return [phase, failure];
    }

    [Theory]
    [MemberData(nameof(MembershipFailureCases))]
    public void Server_membership_failure_never_publishes_or_falls_back(int phase, string failure)
    {
        using var fixture = new IdentityFixture(); var proofCount = 0;
        fixture.MembershipResults = request =>
        {
            if (++proofCount != phase) return [IdentityFixture.MembershipRow(request)];
            switch (failure)
            {
                case "absent": return [];
                case "ambiguous": return [IdentityFixture.MembershipRow(request), IdentityFixture.MembershipRow(request)];
                case "missing-dn": return [new IdentitySearchRow(new Dictionary<string, object[]>())];
                case "denied": throw new UnauthorizedAccessException("controlled denial");
                case "timeout": throw new TimeoutException("controlled timeout");
                case "referral": LdapIdentitySearchSession.RequireCompleteResult(ResultCode.Success, 1); break;
                case "partial": LdapIdentitySearchSession.RequireCompleteResult(ResultCode.SizeLimitExceeded, 0); break;
                default: LdapIdentitySearchSession.RequireCompleteResult(ResultCode.UnavailableCriticalExtension, 0); break;
            }
            throw new Exception("invalid scripted result");
        };
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var state = descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        var error = Record.Exception(() => wrapper.SetOwner(new NTAccount("alice")));
        if (failure == "denied") Assert.IsType<UnauthorizedAccessException>(error);
        else if (failure == "timeout") Assert.IsType<TimeoutException>(error);
        else Assert.IsType<NotSupportedException>(error);
        Assert.Equal(phase, proofCount);
        Assert.Equal(phase == 1 ? 0 : 1, fixture.AccountRequests.Count());
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
        Assert.Same(state, descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(0, descriptor.MutationVersion); Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Server_membership_generation_changes_in_any_proof_phase_reject_mutation(int phase)
    {
        using var fixture = new IdentityFixture(); var proofs = 0;
        fixture.BeforeResponse = request => { if (IdentityFixture.IsMembership(request) && ++proofs == phase) fixture.Entry.Username = "changed"; };
        var wrapper = new FacadeContracts.Wrapper(); fixture.Resolver.Bind(wrapper);
        var state = wrapper.Descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<InvalidOperationException>(() => wrapper.SetOwner(new NTAccount("alice")));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        Assert.Equal(phase == 1 ? 0 : 1, fixture.AccountRequests.Count()); Assert.Equal(1, fixture.Closed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Server_membership_malformed_utf16_dn_refuses_without_publishing(bool returnedRow)
    {
        using var fixture = new IdentityFixture();
        const string malformed = "CN=bad\ud800,DC=example,DC=com";
        if (returnedRow) fixture.Results = _ => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]),
            ("objectClass", ["user"]), ("distinguishedName", [malformed]))];
        else fixture.Entry.Path = "LDAP://dc.example/" + malformed;
        var wrapper = new FacadeContracts.Wrapper(); fixture.Resolver.Bind(wrapper);
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<System.Text.EncoderFallbackException>(() => wrapper.SetOwner(new NTAccount("alice")));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        Assert.Equal(returnedRow ? 1 : 0, fixture.Opened); Assert.Equal(fixture.Opened, fixture.Closed);
        Assert.Equal(returnedRow ? 1 : 0, fixture.AccountRequests.Count());
    }
}
