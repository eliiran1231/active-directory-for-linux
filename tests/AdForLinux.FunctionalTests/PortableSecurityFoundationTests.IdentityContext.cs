#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private sealed class IdentityFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry;
        internal readonly List<SearchRequest> Requests = new();
        internal int Opened, Closed;
        internal Action<SearchRequest>? BeforeResponse;
        internal Func<SearchRequest, IReadOnlyList<IdentitySearchRow>>? Results;
        internal string Name = "alice";
        internal IdentityFixture(bool ambient = false)
        {
            Entry = ambient ? new DirectoryEntry("LDAP://dc.example/DC=example,DC=com")
                : new DirectoryEntry("LDAP://dc.example/DC=example,DC=com", "EXAMPLE\\reader", "test-only", AuthenticationTypes.Secure);
            Entry.IdentitySessionFactory = options =>
            {
                Assert.Equal("dc.example", options.Host);
                Assert.Equal(AuthType.Negotiate, options.AuthenticationType);
                Opened++; return new Session(this);
            };
        }
        internal DirectoryIdentityResolver Resolver => DirectoryIdentityResolver.ForEntry(Entry);
        internal static IdentitySearchRow Row(params (string Name, object[] Values)[] values)
            => new(values.ToDictionary(v => v.Name, v => v.Values, StringComparer.OrdinalIgnoreCase));
        internal IdentitySearchRow Account(byte[]? sid = null) => Row(("objectSid", [sid ?? U1]), ("sAMAccountName", [Name]), ("objectClass", ["top", "person", "user"]));
        private sealed class Session(IdentityFixture fixture) : IIdentitySearchSession
        {
            public IReadOnlyList<IdentitySearchRow> Search(SearchRequest request, TimeSpan remaining)
            {
                Assert.False(Monitor.IsEntered(A.FacadeMutation.Gate));
                Assert.True(remaining > TimeSpan.Zero && remaining <= TimeSpan.FromSeconds(30));
                Assert.Equal(2, request.SizeLimit);
                fixture.Requests.Add(request); fixture.BeforeResponse?.Invoke(request);
                if (request.DistinguishedName == string.Empty)
                    return [Row(("defaultNamingContext", ["DC=example,DC=com"]), ("configurationNamingContext", ["CN=Configuration,DC=example,DC=com"]))];
                if (request.DistinguishedName.StartsWith("CN=Partitions,", StringComparison.Ordinal))
                    return [Row(("nCName", ["DC=example,DC=com"]), ("nETBIOSName", ["EXAMPLE"]), ("dnsRoot", ["example.com"]), ("systemFlags", ["3"]))];
                return fixture.Results?.Invoke(request) ?? [fixture.Account()];
            }
            public void Dispose() => fixture.Closed++;
        }
        public void Dispose() => Entry.Dispose();
    }

    [Fact]
    public void Built_in_identity_resolver_scopes_queries_and_deduplicates_without_cross_operation_cache()
    {
        using var fixture = new IdentityFixture();
        var sid = new SecurityIdentifier(U1, 0);
        var values = new IdentityReferenceCollection { sid, sid, new NTAccount("EXAMPLE", "known") };
        var result = fixture.Resolver.Translate(values, typeof(NTAccount), true);
        Assert.Equal(new[] { "EXAMPLE\\alice", "EXAMPLE\\alice", "EXAMPLE\\known" }, result.Select(x => x.Value));
        Assert.Same(result[0], result[1]);
        Assert.Equal(3, fixture.Requests.Count);
        Assert.Equal(ProtocolScope.Base, fixture.Requests[0].Scope);
        Assert.Equal(ProtocolScope.OneLevel, fixture.Requests[1].Scope);
        Assert.Equal("DC=example,DC=com", fixture.Requests[2].DistinguishedName);
        Assert.Equal(ProtocolScope.Subtree, fixture.Requests[2].Scope);
        Assert.Equal("(&(objectClass=*)(objectSid=" + string.Concat(U1.Select(b => "\\" + b.ToString("x2"))) + "))", fixture.Requests[2].Filter);
        fixture.Name = "renamed";
        Assert.Equal("EXAMPLE\\renamed", fixture.Resolver.Translate(sid, typeof(NTAccount)).Value);
        Assert.Equal(2, fixture.Opened); Assert.Equal(2, fixture.Closed);
    }

    [Theory]
    [InlineData("EXAMPLE\\a*)(x=1)", "sAMAccountName", "a*)(x=1)")]
    [InlineData("example.com\\computer$", "sAMAccountName", "computer$")]
    [InlineData("name@alternate.example", "userPrincipalName", "name@alternate.example")]
    [InlineData("bare", "sAMAccountName", "bare")]
    [InlineData("é😀", "sAMAccountName", "é😀")]
    public void Name_resolution_uses_exact_utf8_filters(string input, string attribute, string value)
    {
        using var fixture = new IdentityFixture();
        Assert.Equal(new SecurityIdentifier(U1, 0), fixture.Resolver.Translate(new NTAccount(input), typeof(SecurityIdentifier)));
        Assert.Equal("(&(objectClass=*)(" + attribute + "=" + AdIdentityLookup.EscapeText(value) + "))", fixture.Requests.Last().Filter);
        Assert.Equal("\\c3\\a9\\f0\\9f\\98\\80", AdIdentityLookup.EscapeText("é😀"));
        Assert.Throws<System.Text.EncoderFallbackException>(() => AdIdentityLookup.EscapeText("\ud800"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("ambiguous")]
    [InlineData("foreign")]
    [InlineData("hidden")]
    [InlineData("wrong-sid")]
    [InlineData("timeout")]
    [InlineData("denied")]
    public void Resolution_errors_are_not_silently_replaced_or_dropped(string kind)
    {
        using var fixture = new IdentityFixture();
        fixture.Results = _ => kind switch
        {
            "missing" => [], "ambiguous" => [fixture.Account(), fixture.Account()],
            "foreign" => [IdentityFixture.Row(("objectSid", [U1]), ("sAMAccountName", ["alice"]), ("objectClass", ["foreignSecurityPrincipal"]))],
            "hidden" => [IdentityFixture.Row(("objectClass", ["user"]))],
            "wrong-sid" => [fixture.Account(U2)],
            "timeout" => throw new TimeoutException("controlled timeout"),
            _ => throw new UnauthorizedAccessException("controlled denial")
        };
        var failure = Record.Exception(() => fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        switch (kind)
        {
            case "missing": case "hidden": Assert.Single(Assert.IsType<IdentityNotMappedException>(failure).UnmappedIdentities); break;
            case "foreign": Assert.IsType<NotSupportedException>(failure); break;
            case "timeout": Assert.IsType<TimeoutException>(failure); break;
            case "denied": Assert.IsType<UnauthorizedAccessException>(failure); break;
            default: Assert.IsType<InvalidOperationException>(failure); break;
        }
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Fact]
    public void Partial_translation_retains_unmapped_identity_and_force_success_reports_it()
    {
        using var fixture = new IdentityFixture(); fixture.Results = _ => [];
        var sid = new SecurityIdentifier(U1, 0); var values = new IdentityReferenceCollection { sid, new NTAccount("known") };
        var resolver = fixture.Resolver;
        var partial = resolver.Translate(values, typeof(NTAccount), false);
        Assert.Same(sid, partial[0]); Assert.Same(values[1], partial[1]);
        Assert.Same(sid, Assert.Single(Assert.Throws<IdentityNotMappedException>(() => resolver.Translate(values, typeof(NTAccount), true)).UnmappedIdentities));
    }

    [Fact]
    public void Ambient_sid_reads_are_allowed_but_name_mutations_require_explicit_authority()
    {
        using var fixture = new IdentityFixture(ambient: true);
        var resolver = fixture.Resolver;
        Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        var count = fixture.Opened;
        Assert.Throws<NotSupportedException>(() => resolver.Translate(new NTAccount("alice"), typeof(SecurityIdentifier)));
        Assert.Equal(count, fixture.Opened);
    }

    [Theory]
    [InlineData("username")]
    [InlineData("password")]
    [InlineData("auth")]
    [InlineData("path")]
    [InlineData("referral")]
    [InlineData("close")]
    [InlineData("dispose")]
    [InlineData("refresh-generation")]
    public void Entry_context_changes_revoke_old_resolution_and_allow_only_explicit_reacquisition(string change)
    {
        using var fixture = new IdentityFixture(); var resolver = fixture.Resolver;
        switch (change)
        {
            case "username": fixture.Entry.Username = "EXAMPLE\\other"; break;
            case "password": fixture.Entry.Password = "changed-test-only"; break;
            case "auth": fixture.Entry.AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Signing; break;
            case "path": fixture.Entry.Path = "LDAP://dc.example/OU=Other,DC=example,DC=com"; break;
            case "referral": fixture.Entry.Options.Referral = ReferralChasingOption.None; break;
            case "close": fixture.Entry.Close(); break;
            case "dispose": fixture.Entry.Dispose(); break;
            default: fixture.Entry.IdentityLifetime.Invalidate(); break; // same hook used after successful descriptor refresh/commit
        }
        var failure = Record.Exception(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        if (change == "dispose") Assert.IsType<ObjectDisposedException>(failure); else Assert.IsType<InvalidOperationException>(failure);
        Assert.Equal(0, fixture.Opened);
        if (change != "dispose") Assert.Equal("EXAMPLE\\alice", fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
    }

    [Theory]
    [InlineData("rebind")]
    [InlineData("dispose")]
    [InlineData("descriptor")]
    [InlineData("attachment")]
    public void Invalidation_during_lookup_refuses_mutation_without_dirty_flags(string change)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var before = descriptor.MutationState;
        fixture.BeforeResponse = _ =>
        {
            fixture.BeforeResponse = null;
            switch (change)
            {
                case "rebind": fixture.Entry.Username = "EXAMPLE\\other"; break;
                case "dispose": fixture.Entry.Dispose(); break;
                case "descriptor": descriptor.Group = new SecurityIdentifier(U2, 0); break;
                case "attachment": fixture.Resolver.Bind(wrapper); break;
            }
        };
        var error = Record.Exception(() => wrapper.SetOwner(new NTAccount("alice")));
        if (change == "dispose") Assert.IsType<ObjectDisposedException>(error); else Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(new SecurityIdentifier(U1, 0), descriptor.Owner);
        if (change != "descriptor") Assert.Same(before, descriptor.MutationState);
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        Assert.Equal(1, fixture.Closed);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    public void Bound_access_routes_resolve_before_atomic_mutation(int route)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, "D:");
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var rule = new FacadeContracts.AR(new NTAccount("EXAMPLE", "alice"), 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty);
        wrapper.AccessRoute(route, rule);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
        Assert.True(wrapper.Flags()[2]);
    }

    [Fact]
    public void Custom_modify_override_can_decline_a_name_rule_without_lookup()
    {
        using var fixture = new IdentityFixture();
        var wrapper = new FacadeContracts.Wrapper { TraceHooks = true }; fixture.Resolver.Bind(wrapper);
        var rule = new FacadeContracts.AR(new NTAccount("alice"), 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty);
        Assert.False(wrapper.ModifyAccessRule(AccessControlModification.Add, rule, out var modified));
        Assert.False(modified); Assert.Equal(0, fixture.Opened);
        Assert.Equal(new[] { "public-access", "protected-access" }, wrapper.Calls);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    public void Bound_audit_routes_resolve_before_atomic_mutation(int route)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, "D:S:");
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var rule = new FacadeContracts.UR(new NTAccount("alice"), 16, false, 0, 0, AuditFlags.Success, Guid.Empty, Guid.Empty);
        wrapper.AuditRoute(route, rule);
        Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
        Assert.True(wrapper.Flags()[3]);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void Bound_owner_group_and_purge_routes_resolve_before_mutation(int route)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1))), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var name = new NTAccount("alice");
        switch (route)
        {
            case 0: wrapper.SetOwner(name); break;
            case 1: wrapper.SetGroup(name); break;
            case 2: wrapper.PurgeAccessRules(name); break;
            case 3: wrapper.PurgeAuditRules(name); break;
        }
        Assert.True(wrapper.Flags()[route]); Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed);
    }

    [Fact]
    public void Lookup_releases_library_write_locks_and_rejects_concurrent_descriptor_changes()
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, "D:");
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        fixture.BeforeResponse = _ =>
        {
            fixture.BeforeResponse = null;
            Exception? failure = null;
            var worker = new Thread(() =>
            {
                try { wrapper.EnterWrite(); try { descriptor.Owner = new SecurityIdentifier(U2, 0); } finally { wrapper.ExitWrite(); } }
                catch (Exception error) { failure = error; }
            });
            worker.Start(); Assert.True(worker.Join(TimeSpan.FromSeconds(5))); Assert.Null(failure);
        };
        var rule = new FacadeContracts.AR(new NTAccount("alice"), 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty);
        Assert.Throws<InvalidOperationException>(() => wrapper.ModifyAccessRule(AccessControlModification.Add, rule, out _));
        Assert.Empty(descriptor.DiscretionaryAcl!.Cast<A.GenericAce>());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Fact]
    public void Caller_held_security_lock_is_never_silently_released_for_lookup()
    {
        using var fixture = new IdentityFixture(); var wrapper = new FacadeContracts.Wrapper(); fixture.Resolver.Bind(wrapper);
        wrapper.EnterWrite();
        try { Assert.Throws<InvalidOperationException>(() => wrapper.SetOwner(new NTAccount("alice"))); }
        finally { wrapper.ExitWrite(); }
        Assert.Equal(0, fixture.Opened);
    }

    [Fact]
    public void Descriptor_and_wrapper_copies_never_inherit_resolver_authority()
    {
        using var source = new IdentityFixture(); using var destination = new IdentityFixture { Name = "destination" };
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0);
        var first = new FacadeContracts.Wrapper(descriptor); source.Resolver.Bind(first);
        var shared = new FacadeContracts.Wrapper(descriptor);
        var copy = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, first.GetSecurityDescriptorBinaryForm(), 0));
        Assert.Throws<NotSupportedException>(() => shared.GetOwner(typeof(NTAccount)));
        Assert.Throws<NotSupportedException>(() => copy.GetOwner(typeof(NTAccount)));
        destination.Resolver.Bind(copy);
        source.Entry.Dispose();
        Assert.Throws<ObjectDisposedException>(() => first.GetOwner(typeof(NTAccount)));
        Assert.Equal("EXAMPLE\\destination", copy.GetOwner(typeof(NTAccount))!.Value);
        Assert.Equal(new SecurityIdentifier(U1, 0), first.GetOwner(typeof(SecurityIdentifier)));
        copy.SetOwner(new SecurityIdentifier(U2, 0));
        Assert.Equal(new SecurityIdentifier(U1, 0), descriptor.Owner);
    }

    [Fact]
    public void Rule_translation_resolves_only_selected_rules_outside_shared_locks()
    {
        using var fixture = new IdentityFixture();
        var raw = Build(U1, U1, Acl(4, Ace(9, 0, 32, U2), Ace(0, 0, 16, U1), Ace(0, 0x12, 16, U2)), null);
        var wrapper = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, raw, 0)); fixture.Resolver.Bind(wrapper);
        var rules = wrapper.GetAccessRules(true, false, typeof(NTAccount)).Cast<A.AccessRule>().ToArray();
        Assert.Single(rules); Assert.Equal("EXAMPLE\\alice", rules[0].IdentityReference.Value);
        Assert.Equal(3, fixture.Requests.Count);
    }

    [Fact]
    public void Prepared_identity_revalidates_authority_at_final_publication()
    {
        using var fixture = new IdentityFixture(); var wrapper = new FacadeContracts.Wrapper(); fixture.Resolver.Bind(wrapper);
        using var prepared = wrapper.PrepareIdentityMutation(new NTAccount("alice"));
        var before = wrapper.Descriptor.MutationState;
        fixture.Entry.Username = "EXAMPLE\\other";
        Assert.Throws<InvalidOperationException>(() => prepared.Run(() => wrapper.Descriptor.Owner = prepared.Sid));
        Assert.Same(before, wrapper.Descriptor.MutationState);
    }

    [Fact]
    public void Invalid_mutation_and_malformed_name_fail_before_lookup()
    {
        using var fixture = new IdentityFixture(); var wrapper = new FacadeContracts.Wrapper(); fixture.Resolver.Bind(wrapper);
        var rule = new FacadeContracts.AR(new NTAccount("alice"), 16, false, 0, 0, AccessControlType.Allow, Guid.Empty, Guid.Empty);
        Assert.Throws<ArgumentOutOfRangeException>(() => wrapper.ModifyAccessRule((AccessControlModification)99, rule, out _));
        Assert.Throws<System.Text.EncoderFallbackException>(() => fixture.Resolver.Translate(new NTAccount("\ud800"), typeof(SecurityIdentifier)));
        Assert.Equal(0, fixture.Opened);
    }
}
