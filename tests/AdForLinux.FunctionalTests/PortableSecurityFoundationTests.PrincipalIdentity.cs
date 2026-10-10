#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Runtime.CompilerServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private sealed class PrincipalIdentityFixture : IDisposable
    {
        internal readonly IdentityFixture Transport = new();
        internal readonly PrincipalContext Context;
        internal LdapConnectionOptions? Captured;
        internal PrincipalIdentityFixture(string? container = null, bool ambient = false,
            string server = "dc.example:1636", ContextOptions options = ContextOptions.Negotiate | ContextOptions.SecureSocketLayer | ContextOptions.Signing | ContextOptions.Sealing)
        {
            Context = new PrincipalContext(ContextType.Domain, server, container, options,
                ambient ? null : "EXAMPLE\\reader", ambient ? null : "test-only");
            Context.IdentitySessionFactory = value => { Captured = value; return Transport.CreateSession(); };
        }
        internal DirectoryIdentityResolver Resolver => Context.CreateIdentityResolver();
        public void Dispose() { Context.Dispose(); Transport.Dispose(); }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("DC=example,DC=com")]
    [InlineData("OU=Research and Dévelopment,DC=example,DC=com")]
    public void Principal_resolver_borrows_options_and_proves_container_without_eager_discovery(string? container)
    {
        using var fixture = new PrincipalIdentityFixture(container);
        var resolver = fixture.Resolver;
        Assert.Equal(0, fixture.Transport.Opened); Assert.Null(fixture.Captured);
        Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        Assert.Equal("dc.example", fixture.Captured!.Host); Assert.Equal(1636, fixture.Captured.Port);
        Assert.True(fixture.Captured.UseSsl); Assert.True(fixture.Captured.Signing); Assert.True(fixture.Captured.Sealing);
        Assert.Equal(AuthType.Negotiate, fixture.Captured.AuthenticationType);
        Assert.Equal("EXAMPLE\\reader", fixture.Captured.BindDn); Assert.Equal("test-only", fixture.Captured.BindPassword);
        var proofs = fixture.Transport.Requests.Where(IdentityFixture.IsMembership).ToArray();
        Assert.Equal(container ?? "DC=example,DC=com", IdentityFixture.MembershipTarget(proofs[0]));
        Assert.Equal(IdentityFixture.MembershipTarget(proofs[0]), IdentityFixture.MembershipTarget(proofs[^1]));
        Assert.All(fixture.Transport.Requests.Where(r => r.Scope == System.DirectoryServices.Protocols.SearchScope.Subtree),
            r => Assert.Equal("DC=example,DC=com", r.DistinguishedName));
        Assert.Null(typeof(PrincipalContext).GetField("_searchRoot", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(fixture.Context));
        Assert.Equal(1, fixture.Transport.Opened); Assert.Equal(1, fixture.Transport.Closed);
    }

    [Fact]
    public void Principal_resolver_preserves_explicit_simple_bind_policy()
    {
        using var fixture = new PrincipalIdentityFixture(options: ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer);
        Assert.Equal(new SecurityIdentifier(U1, 0), fixture.Resolver.Translate(new NTAccount("alice"), typeof(SecurityIdentifier)));
        Assert.Equal(AuthType.Basic, fixture.Captured!.AuthenticationType);
        Assert.False(fixture.Captured.Signing); Assert.False(fixture.Captured.Sealing); Assert.True(fixture.Captured.UseSsl);
    }

    [Theory]
    [InlineData(3268)]
    [InlineData(3269)]
    public void Principal_resolver_gc_ports_refuse_before_opening(int port)
    {
        using var fixture = new PrincipalIdentityFixture(server: "dc.example:" + port);
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(0, fixture.Transport.Opened);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Principal_resolver_explicit_empty_container_is_not_default_domain_authority(string container)
    {
        using var fixture = new PrincipalIdentityFixture(container);
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(0, fixture.Transport.Opened);
    }

    [Theory]
    [InlineData("CN=user,DC=child,DC=example,DC=com")]
    [InlineData("CN=user,CN=App Pärtition,DC=example,DC=com")]
    public void Principal_resolver_unverified_container_never_falls_back_to_default_domain(string container)
    {
        using var fixture = new PrincipalIdentityFixture(container); fixture.Transport.MembershipResults = _ => [];
        Assert.Throws<NotSupportedException>(() => fixture.Resolver.Translate(new NTAccount("alice"), typeof(SecurityIdentifier)));
        Assert.Empty(fixture.Transport.AccountRequests); Assert.Equal(1, fixture.Transport.Closed);
    }

    [Fact]
    public void Principal_resolver_ambient_reads_do_not_enable_name_mutation()
    {
        using var fixture = new PrincipalIdentityFixture(ambient: true); var resolver = fixture.Resolver;
        Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        var wrapper = new FacadeContracts.Wrapper(); resolver.Bind(wrapper);
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.SetOwner(new NTAccount("alice")));
        Assert.Equal(1, fixture.Transport.Opened); Assert.Same(state, wrapper.Descriptor.MutationState);
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Fact]
    public void Principal_resolver_disposal_revokes_authority_but_retains_sid_data_and_edits()
    {
        using var fixture = new PrincipalIdentityFixture(); var resolver = fixture.Resolver;
        var wrapper = new FacadeContracts.Wrapper(); resolver.Bind(wrapper);
        wrapper.SetOwner(new SecurityIdentifier(U1, 0)); var state = wrapper.Descriptor.MutationState;
        fixture.Context.Dispose();
        Assert.Throws<ObjectDisposedException>(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Throws<ObjectDisposedException>(() => resolver.Bind(new FacadeContracts.Wrapper()));
        Assert.Throws<ObjectDisposedException>(() => fixture.Context.CreateIdentityResolver());
        Assert.Same(state, wrapper.Descriptor.MutationState);
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        wrapper.SetGroup(new SecurityIdentifier(U2, 0));
        Assert.Equal(new SecurityIdentifier(U2, 0), wrapper.GetGroup(typeof(SecurityIdentifier)));
        Assert.Equal(0, fixture.Transport.Opened);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Principal_resolver_dispose_during_each_proof_refuses_atomic_publication(int phase)
    {
        using var fixture = new PrincipalIdentityFixture(); var proofs = 0;
        fixture.Transport.BeforeResponse = request =>
        {
            if (IdentityFixture.IsMembership(request) && ++proofs == phase) fixture.Context.Dispose();
        };
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U2, U2, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper);
        var state = descriptor.MutationState; var bytes = wrapper.GetSecurityDescriptorBinaryForm();
        Assert.Throws<ObjectDisposedException>(() => wrapper.SetOwner(new NTAccount("alice")));
        Assert.Same(state, descriptor.MutationState); Assert.Equal(bytes, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags()); Assert.Equal(0, descriptor.MutationVersion);
        Assert.Equal(1, fixture.Transport.Opened); Assert.Equal(1, fixture.Transport.Closed);
    }

    [Fact]
    public void Principal_resolver_io_does_not_hold_owner_disposal_gate()
    {
        using var fixture = new PrincipalIdentityFixture();
        fixture.Transport.BeforeResponse = request =>
        {
            fixture.Transport.BeforeResponse = null;
            var dispose = Task.Run(fixture.Context.Dispose);
            Assert.True(dispose.Wait(TimeSpan.FromSeconds(5)), "Context disposal must progress while the lookup is in flight.");
            dispose.GetAwaiter().GetResult();
        };
        Assert.Throws<ObjectDisposedException>(() => fixture.Resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(1, fixture.Transport.Closed);
    }

    [Fact]
    public void Principal_independent_entry_keeps_its_existing_lifetime_after_context_disposal()
    {
        using var fixture = new PrincipalIdentityFixture();
        using var child = fixture.Context.CreateDirectoryEntry("DC=example,DC=com");
        child.IdentitySessionFactory = _ => fixture.Transport.CreateSession();
        var entryResolver = DirectoryIdentityResolver.ForEntry(child); var contextResolver = fixture.Resolver;
        fixture.Context.Dispose();
        Assert.Throws<ObjectDisposedException>(() => contextResolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal("EXAMPLE\\alice", entryResolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
        Assert.Equal(1, fixture.Transport.Opened); Assert.Equal(1, fixture.Transport.Closed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Principal_context_descriptor_copies_transfer_data_only(bool sharedDescriptor)
    {
        using var source = new PrincipalIdentityFixture(); using var destination = new PrincipalIdentityFixture();
        var original = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0));
        source.Resolver.Bind(original);
        var copy = new FacadeContracts.Wrapper(sharedDescriptor ? original.Descriptor
            : new A.CommonSecurityDescriptor(true, true, original.GetSecurityDescriptorBinaryForm(), 0));
        Assert.Throws<NotSupportedException>(() => copy.GetOwner(typeof(NTAccount)));
        Assert.Equal(0, source.Transport.Opened); Assert.Equal(0, destination.Transport.Opened);
        source.Context.Dispose(); destination.Transport.Name = "destination"; destination.Resolver.Bind(copy);
        Assert.Equal("EXAMPLE\\destination", copy.GetOwner(typeof(NTAccount))!.Value);
        Assert.Throws<ObjectDisposedException>(() => original.GetOwner(typeof(NTAccount)));
        Assert.Equal(0, source.Transport.Opened); Assert.Equal(1, destination.Transport.Opened);
    }

    [Fact]
    public void Principal_context_resolution_is_not_entry_raw_write_provenance()
    {
        using var fixture = new PrincipalIdentityFixture(); var resolver = fixture.Resolver;
        var wrapper = new FacadeContracts.Wrapper(); resolver.Bind(wrapper);
        Assert.Throws<NotSupportedException>(() => resolver.GetReadOrigin());
        Assert.Throws<NotSupportedException>(() => wrapper.SetRawReadContext(AdForLinux.DirectoryServices.SecurityMasks.Owner, resolver));
        Assert.False(wrapper.HasRawReadContext); Assert.Equal(0, fixture.Transport.Opened);
    }

    [Fact]
    public void Principal_public_resolver_factory_preserves_dependency_direction()
    {
        Assert.Equal(typeof(DirectoryIdentityResolver), typeof(PrincipalContext).GetMethod("CreateIdentityResolver", BindingFlags.Public | BindingFlags.Instance)!.ReturnType);
        Assert.DoesNotContain(typeof(DirectoryIdentityResolver).Assembly.GetReferencedAssemblies(),
            assembly => assembly.Name == typeof(PrincipalContext).Assembly.GetName().Name);
        Assert.Equal(typeof(SecurityIdentifier), typeof(Principal).GetProperty("Sid")!.PropertyType);
    }

    [Fact]
    public void Principal_default_domain_support_does_not_broaden_entry_without_target()
    {
        using var entry = new DirectoryEntry("LDAP://dc.example");
        entry.IdentitySessionFactory = _ => throw new Exception("No session should open.");
        Assert.Throws<NotSupportedException>(() => DirectoryIdentityResolver.ForEntry(entry)
            .Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (Task<IdentityReference> Work, DirectoryIdentityResolver Resolver, WeakReference Owner)
        StartPrincipalOperation(IdentityFixture transport, ManualResetEventSlim entered, ManualResetEventSlim release)
    {
        var context = new PrincipalContext(ContextType.Domain, "dc.example");
        context.IdentitySessionFactory = _ => transport.CreateSession();
        transport.BeforeResponse = _ => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10))); };
        var resolver = context.CreateIdentityResolver();
        var work = Task.Run(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        return (work, resolver, new WeakReference(context));
    }

    [Fact]
    public async Task Principal_operation_holds_only_a_temporary_owner_lease()
    {
        using var transport = new IdentityFixture(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var (work, resolver, owner) = StartPrincipalOperation(transport, entered, release);
        try { GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); Assert.True(owner.IsAlive); }
        finally { release.Set(); }
        Assert.Equal("EXAMPLE\\alice", (await work).Value);
        for (var attempt = 0; attempt < 3 && owner.IsAlive; attempt++) { GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); }
        Assert.False(owner.IsAlive);
        Assert.Throws<ObjectDisposedException>(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(1, transport.Opened); Assert.Equal(1, transport.Closed);
        GC.KeepAlive(resolver); GC.KeepAlive(work);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (DirectoryIdentityResolver Resolver, WeakReference Owner) CreateWeakPrincipalResolver()
    {
        var context = new PrincipalContext(ContextType.Domain, "dc.example");
        return (context.CreateIdentityResolver(), new WeakReference(context));
    }

    [Fact]
    public void Principal_resolver_does_not_retain_its_owner_or_revive_collected_credentials()
    {
        var (resolver, owner) = CreateWeakPrincipalResolver();
        for (var attempt = 0; attempt < 3 && owner.IsAlive; attempt++) { GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); }
        Assert.False(owner.IsAlive);
        Assert.Throws<ObjectDisposedException>(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        Assert.Equal(new SecurityIdentifier(U1, 0), resolver.Translate(new SecurityIdentifier(U1, 0), typeof(SecurityIdentifier)));
        GC.KeepAlive(resolver);
    }
}
