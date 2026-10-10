using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Interop_current_entry_or_context_binding_allows_local_apply_without_lookup(bool contextBinding, bool edited)
    {
        using var fixture = new IdentityFixture();
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        context.IdentitySessionFactory = _ => throw new Exception("No lookup is allowed.");
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        var resolver = contextBinding ? context.CreateIdentityResolver() : fixture.Resolver;
        if (!contextBinding) source.SetRawReadContext((SecurityMasks)15, resolver);
        resolver.Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        Assert.Equal(edited ? SecurityMasks.Owner : SecurityMasks.None,
            source.ReconcileInterop(export.Provenance, edited ? InteropOwner(export.Value, U2) : export.Value));
        Assert.Equal(0, fixture.Opened);
    }

    public static IEnumerable<object[]> InteropRevocations()
    {
        foreach (var change in new[] { "close", "dispose", "path", "username", "password", "refresh", "context-dispose", "context-generation" })
            foreach (var changed in new[] { false, true }) yield return new object[] { change, changed };
    }

    [Theory]
    [MemberData(nameof(InteropRevocations))]
    public void Interop_apply_checks_current_owner_lifetime_including_noop(string change, bool changed)
    {
        using var fixture = new IdentityFixture();
        using var context = new PrincipalContext(ContextType.Domain, "dc.example");
        context.IdentitySessionFactory = _ => throw new Exception("No identity lookup is allowed.");
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        var resolver = change.StartsWith("context") ? context.CreateIdentityResolver() : fixture.Resolver;
        resolver.Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = changed ? InteropOwner(export.Value, U2) : export.Value;
        var before = source.CaptureInteropSnapshot();
        switch (change)
        {
            case "close": fixture.Entry.Close(); break;
            case "dispose": fixture.Entry.Dispose(); break;
            case "path": fixture.Entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
            case "username": fixture.Entry.Username = "EXAMPLE\\other"; break;
            case "password": fixture.Entry.Password = "changed-test-only"; break;
            case "refresh": fixture.Entry.PropertyReadOverride = (_, _) => new PropertyCollection(); fixture.Entry.RefreshCache(new[] { "nTSecurityDescriptor" }); break;
            case "context-dispose": context.Dispose(); break;
            default: context.IdentityLifetime.Invalidate(); break;
        }
        Assert.ThrowsAny<InvalidOperationException>(() => source.ReconcileInterop(export.Provenance, candidate));
        var after = source.CaptureInteropSnapshot();
        Assert.Equal(before.Raw, after.Raw); Assert.Equal(before.Pending, after.Pending);
        Assert.Equal(before.Generation, after.Generation); Assert.Equal(before.Attachment, after.Attachment);
        Assert.Equal(0, fixture.Opened);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Interop_revocation_while_apply_waits_for_wrapper_lock_refuses_atomically(bool changed)
    {
        using var fixture = new IdentityFixture();
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        fixture.Resolver.Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = changed ? InteropOwner(export.Value, U2) : export.Value;
        using var started = new ManualResetEventSlim();
        Task<Exception?> work;
        source.EnterWrite();
        try
        {
            work = Task.Run<Exception?>(() => { started.Set(); return Record.Exception(() => source.ReconcileInterop(export.Provenance, candidate)); });
            Assert.True(started.Wait(TimeSpan.FromSeconds(10)));
            fixture.Entry.Close();
        }
        finally { source.ExitWrite(); }
        Assert.IsAssignableFrom<InvalidOperationException>(await work.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(export.Provenance.Snapshot.Raw, source.CaptureInteropSnapshot().Raw);
        Assert.Equal(SecurityMasks.None, source.PendingWriteSections);
        Assert.Equal(0, fixture.Opened);
    }

    [Fact]
    public void Interop_apply_refuses_resolver_that_does_not_match_retained_read_origin()
    {
        using var original = new IdentityFixture(); using var other = new IdentityFixture();
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        source.SetRawReadContext((SecurityMasks)15, original.Resolver);
        other.Resolver.Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        Assert.Throws<InvalidOperationException>(() => source.ReconcileInterop(export.Provenance, export.Value));
        Assert.Equal(export.Provenance.Snapshot.Raw, source.CaptureInteropSnapshot().Raw);
        Assert.Equal(0, original.Opened); Assert.Equal(0, other.Opened);
    }

    private sealed class InteropLifetimeBinding : IdentityResolverBinding, IDisposable
    {
        internal readonly IdentityContextLifetime Lifetime = new();
        internal readonly ManualResetEventSlim Entered = new(), Release = new();
        internal bool Block;
        internal override long Capture() => Lifetime.Capture(() => { });
        internal override T Checked<T>(long generation, Func<T> action) => Lifetime.Checked(generation, () => { }, () =>
        {
            // Test-only scheduling point, not a production callback or I/O hook.
            Assert.False(Monitor.IsEntered(A.FacadeMutation.Gate));
            if (Block) { Entered.Set(); Assert.True(Release.Wait(TimeSpan.FromSeconds(10))); }
            return action();
        });
        internal override IdentityResolutionOperation Acquire(long generation) => throw new Exception("No session may open.");
        public void Dispose() { Entered.Dispose(); Release.Dispose(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Interop_owner_lifetime_spans_atomic_publication_without_holding_shared_gate_while_waiting(bool edited)
    {
        using var binding = new InteropLifetimeBinding();
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        DirectoryIdentityResolver.ForBinding(binding).Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = edited ? InteropOwner(export.Value, U2) : export.Value;
        binding.Block = true;
        var apply = Task.Run(() => source.ReconcileInterop(export.Provenance, candidate));
        Task? revoke = null;
        try
        {
            Assert.True(binding.Entered.Wait(TimeSpan.FromSeconds(10)));
            using var started = new ManualResetEventSlim();
            revoke = Task.Run(() => { started.Set(); binding.Lifetime.Invalidate(); });
            Assert.True(started.Wait(TimeSpan.FromSeconds(10)));
            Assert.NotSame(revoke, await Task.WhenAny(revoke, Task.Delay(100)));
            var peer = InteropWrapper(Build(U1, U1, Acl(4)));
            await Task.Run(() => peer.SetOwner(new AdForLinux.Security.Principal.SecurityIdentifier(U2, 0))).WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            binding.Release.Set();
            await Task.WhenAll(apply, revoke ?? Task.CompletedTask).WaitAsync(TimeSpan.FromSeconds(10));
        }
        Assert.Equal(edited ? SecurityMasks.Owner : SecurityMasks.None, await apply.WaitAsync(TimeSpan.FromSeconds(10)));
        if (revoke is not null) await revoke.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Throws<InvalidOperationException>(() => source.ReconcileInterop(export.Provenance, candidate));
    }

    [Fact]
    public void Interop_apply_rejects_caller_held_shared_gate_before_borrowing_a_lifetime()
    {
        using var binding = new InteropLifetimeBinding();
        var source = InteropWrapper(Build(U1, U1, Acl(4)));
        DirectoryIdentityResolver.ForBinding(binding).Bind(source);
        var export = source.ExportInterop(InteropRoundTrip, bytes => bytes);
        lock (A.FacadeMutation.Gate)
            Assert.Throws<InvalidOperationException>(() => source.ReconcileInterop(export.Provenance, export.Value));
    }
}
