using AdForLinux.DirectoryServices;
using Xunit;
using AdForLinux.Security.Principal;
using AdForLinux.Tests.Shared;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> DetachedCoverageMatrix() => DetachedCoverageCases.Matrix();

    [Fact]
    public void Detached_partial_AD_owner_edit_cannot_disappear_from_snapshot_intent()
    {
        var source = new ActiveDirectorySecurity(DetachedCoverageCases.Baseline(), SecurityMasks.Dacl);
        var before = source.CaptureInteropSnapshot();
        Assert.False(source.HasRawReadContext);
        source.SetOwner(new SecurityIdentifier(U2, 0));
        Assert.NotEqual(before.Raw, source.CaptureInteropSnapshot().Raw);
        Assert.Equal(SecurityMasks.Owner, source.PendingWriteSections);
        Assert.Equal(SecurityMasks.Dacl, source.CaptureInteropSnapshot().Retrieved);
        Assert.Equal(source.PendingWriteSections, source.CaptureInteropSnapshot().Pending);
        using var fixture = new EntryWriteFixture();
        var destination = fixture.Entry.ObjectSecurity;
        var destinationBefore = destination.CaptureInteropSnapshot();
        Assert.Throws<InvalidOperationException>(() => fixture.Entry.ObjectSecurity = source);
        Assert.Same(destination, fixture.Entry.ObjectSecurity);
        Assert.Equal(destinationBefore.Raw, destination.CaptureInteropSnapshot().Raw);
        Assert.Empty(fixture.Writes);
    }

    [Theory]
    [MemberData(nameof(DetachedCoverageMatrix))]
    public void Detached_AD_snapshot_keeps_coverage_and_intent_separate_on_all_mutation_routes(int mask, string operation, int required)
    {
        var source = new ActiveDirectorySecurity(DetachedCoverageCases.Baseline(), (SecurityMasks)mask);
        var before = source.CaptureInteropSnapshot();
        if ((operation.StartsWith("typed-add-") || operation.StartsWith("modify-")) && (required & ~mask) != 0)
        {
            Assert.Throws<InvalidOperationException>(() => DetachedCoverageCases.Apply(source, operation));
            var after = source.CaptureInteropSnapshot();
            Assert.Equal(before.Raw, after.Raw); Assert.Equal(before.Observable, after.Observable);
            Assert.Equal(before.Original, after.Original); Assert.Equal(before.Generation, after.Generation);
            Assert.Equal(before.Pending, after.Pending);
            Assert.Equal(SecurityMasks.None, source.AssignmentSections);
        }
        else
        {
            DetachedCoverageCases.Apply(source, operation);
            Assert.Equal((SecurityMasks)required, source.PendingWriteSections);
            Assert.Equal(source.PendingWriteSections, source.CaptureInteropSnapshot().Pending);
        }
        Assert.Equal((SecurityMasks)mask, source.CaptureInteropSnapshot().Retrieved);
        Assert.False(source.HasRawReadContext); Assert.Null(source.CaptureIdentityRead().Resolver);
        if (!(operation.StartsWith("typed-add-") || operation.StartsWith("modify-")) && (required & ~mask) != 0)
        {
            using var fixture = new EntryWriteFixture();
            var destination = fixture.Entry.ObjectSecurity;
            var beforeAssignment = destination.CaptureInteropSnapshot();
            Assert.Throws<InvalidOperationException>(() => fixture.Entry.ObjectSecurity = source);
            Assert.Same(destination, fixture.Entry.ObjectSecurity);
            Assert.Equal(beforeAssignment.Raw, destination.CaptureInteropSnapshot().Raw);
            Assert.Equal(beforeAssignment.Pending, destination.CaptureInteropSnapshot().Pending);
            Assert.Empty(fixture.Writes);
        }
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(15)]
    public void Companion_snapshot_coverage_never_promotes_AD_import_masks(int mask)
    {
        var raw = Build(U1, U1, Acl(4), Acl(4));
        var source = new ActiveDirectorySecurity(raw, (SecurityMasks)mask);
        var snapshot = source.CaptureInteropSnapshot();
        Assert.Equal((SecurityMasks)mask, snapshot.Retrieved);
        Assert.Equal(SecurityMasks.None, snapshot.Pending);
        Assert.Equal(raw, snapshot.Raw);
        var called = false;
        byte[] Construct(byte[] bytes, bool container, bool directory) { called = true; return bytes; }
        if (mask == 15) source.ExportInterop(Construct, bytes => bytes);
        else Assert.Throws<NotSupportedException>(() => source.ExportInterop(Construct, bytes => bytes));
        Assert.Equal(mask == 15, called);
        Assert.False(source.HasRawReadContext);
        Assert.Null(source.CaptureIdentityRead().Resolver);
    }
}
