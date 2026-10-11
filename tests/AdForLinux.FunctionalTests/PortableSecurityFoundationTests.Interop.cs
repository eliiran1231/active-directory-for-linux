#pragma warning disable CA1416
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using C = AdForLinux.DirectoryServices.Security.Core;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static FacadeContracts.Wrapper InteropWrapper(byte[] bytes)
        => new(new A.CommonSecurityDescriptor(true, true, bytes, 0));

    // Windows executes actual framework construction/serialization. Linux exercises
    // the same internal boundary against the portable detached target; no recordings
    // are synthesized and no Windows execution is claimed for the Linux branch.
    private static byte[] InteropRoundTrip(byte[] bytes, bool container, bool directory)
    {
        if (OperatingSystem.IsWindows())
        {
            var native = new System.Security.AccessControl.CommonSecurityDescriptor(container, directory, bytes, 0);
            var result = new byte[native.BinaryLength]; native.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(container, directory, bytes, 0);
        return A.FacadeMutation.Bytes(portable);
    }

    private static byte[] InteropOwner(byte[] bytes, byte[] owner)
    {
        if (OperatingSystem.IsWindows())
        {
            var native = new System.Security.AccessControl.CommonSecurityDescriptor(true, true, bytes, 0);
            native.Owner = new System.Security.Principal.SecurityIdentifier(owner, 0);
            var result = new byte[native.BinaryLength]; native.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(true, true, bytes, 0) { Owner = new SecurityIdentifier(owner, 0) };
        return A.FacadeMutation.Bytes(portable);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    [InlineData(5)] [InlineData(6)]
    public void Interop_UnchangedExportsNeverCreateIntent(int variant)
    {
        var dacl = variant switch
        {
            0 or 1 => null,
            2 => Acl(4),
            3 => Acl(4, Ace(0, 4, 16, U1)), // approved NoPropagate normalization
            4 => Acl(4, Ace(0, 8, 16, U1)), // approved inactive ACE omission
            5 => Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)), // projection compaction
            _ => Acl(4, ObjAce(5, 0, 16, 1, G1, null, U1), Ace(0, 0, 32, U1))
        };
        var original = Build(U1, U1, dacl, Acl(4, Ace(2, 0x48, 16, U1), Ace(2, 0x40, 32, U2)), nullDacl: variant == 1);
        var wrapper = InteropWrapper(original);
        var before = wrapper.Descriptor.MutationState;
        var snapshot = wrapper.CaptureInteropSnapshot();
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        Assert.Same(before, wrapper.Descriptor.MutationState);
        Assert.Equal(original, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
        Assert.Equal(original, snapshot.Raw);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Portable_OwnerEditPreservesRawAclContributorsAndSharedDescriptor(bool nullDacl)
    {
        var original = Build(U1, U1, nullDacl ? null : Acl(4, Ace(0, 8, 16, U1), Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)),
            Acl(4, Ace(2, 0x48, 16, U1), Ace(2, 0xC0, 32, U2)), nullDacl: nullDacl);
        var wrapper = InteropWrapper(original);
        var shared = new FacadeContracts.Wrapper(wrapper.Descriptor);
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        wrapper.SetOwner(new SecurityIdentifier(U2, 0));
        Assert.Equal(new SecurityIdentifier(U2, 0), shared.GetOwner(typeof(SecurityIdentifier)));
        var expected = C.DescriptorRewriter.Rewrite(C.SecurityDescriptor.Parse(original, (SecurityMasks)15),
            C.SecurityDescriptor.Parse(original, (SecurityMasks)15).Control, new Dictionary<SecurityMasks, byte[]?> { [SecurityMasks.Owner] = U2 });
        Assert.Equal(expected.GetBinaryForm(), wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Owner, wrapper.PendingWriteSections);
        Assert.Equal(new[] { true, false, false, false }, wrapper.Flags());
        Assert.Equal(new[] { false, false, false, false }, shared.Flags());
        Assert.Equal(new SecurityIdentifier(U1, 0), new A.RawSecurityDescriptor(export, 0).Owner);
    }

    [Fact]
    public void Interop_EditRevertAndDetachedExportDoNotInferIntent()
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        var plain = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        _ = InteropOwner(plain, U2);
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        var snapshot = wrapper.CaptureInteropSnapshot();
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        var reverted = InteropOwner(InteropOwner(export, U2), U1);
        Assert.Equal(export, reverted);
        Assert.Equal(snapshot.Raw, wrapper.CaptureInteropSnapshot().Raw);
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(8)]
    public void Interop_UnreadSectionsRefuseBeforeTargetConstruction(int retrieved)
    {
        using var fixture = new IdentityFixture();
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        wrapper.SetRawReadContext((SecurityMasks)retrieved, fixture.Resolver);
        var snapshot = wrapper.CaptureInteropSnapshot();
        Assert.Equal((SecurityMasks)retrieved, snapshot.Retrieved);
        var called = false;
        Assert.Throws<NotSupportedException>(() => wrapper.ExportDetachedInterop((bytes, _, _) => { called = true; return bytes; }, bytes => bytes));
        Assert.False(called);
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
    }

    [Fact]
    public void Interop_SnapshotCopiesContainNoCapabilitiesAndCannotModifySource()
    {
        using var fixture = new IdentityFixture();
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        fixture.Resolver.Bind(wrapper);
        var snapshot = wrapper.CaptureInteropSnapshot();
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        var savedRaw = snapshot.Raw; var savedOriginal = snapshot.Original; var savedObservable = snapshot.Observable;
        foreach (var bytes in new[] { snapshot.Raw,
            snapshot.Original, snapshot.Observable }) Array.Fill(bytes, (byte)0);
        Assert.Equal(savedRaw,snapshot.Raw); Assert.Equal(savedOriginal,snapshot.Original); Assert.Equal(savedObservable,snapshot.Observable);
        Assert.Equal(savedRaw,wrapper.CaptureInteropSnapshot().Raw);
        foreach (var type in new[] { typeof(A.InteropSnapshot) })
            foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
                Assert.True(field.FieldType.IsValueType || field.FieldType == typeof(byte[]) || field.FieldType == typeof(A.InteropSnapshot), field.ToString());
        Assert.Equal(0, fixture.Opened);
    }

    [Fact]
    public void Interop_ExternalConstructionRunsOutsidePortableLocks()
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        var export = wrapper.ExportDetachedInterop((bytes, container, directory) =>
        {
            var completed = Task.Run(() => wrapper.SetGroup(new SecurityIdentifier(U2, 0))).Wait(TimeSpan.FromSeconds(5));
            Assert.True(completed);
            return InteropRoundTrip(bytes, container, directory);
        }, bytes => bytes);
        Assert.Equal(new SecurityIdentifier(U1, 0), new A.RawSecurityDescriptor(export, 0).Owner);
    }

    [Fact]
    public void Interop_TargetLossFailsBeforePublishingAndRetainsRawData()
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4), Acl(4, Ace(2, 0x40, 16, U1))));
        var before = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ExportDetachedInterop((_, _, _) => Build(U1, U1, Acl(4)), bytes => bytes));
        Assert.Same(before, wrapper.Descriptor.MutationState);
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
    }

    [Fact]
    public void InteropAcl_UnrelatedOpaqueAuditDataRefusesExportWithoutMutation()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)),
            Acl(4, Ace(13, 0x40, 16, U1, new byte[] { 1, 2, 3, 4 })));
        var wrapper = InteropWrapper(raw);
        var state = wrapper.Descriptor.MutationState;
        var generation = wrapper.Descriptor.MutationVersion;
        var called = false;
        Assert.Throws<InvalidOperationException>(() => wrapper.ExportDetachedInterop((bytes, container, directory) =>
        {
            called = true;
            return InteropRoundTrip(bytes, container, directory);
        }, bytes => bytes));
        Assert.False(called);
        Assert.Same(state, wrapper.Descriptor.MutationState);
        Assert.Equal(generation, wrapper.Descriptor.MutationVersion);
        Assert.Equal(raw, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void Interop_UnverifiedDataRefusesWithoutDroppingOriginals(int variant)
    {
        var raw = variant switch
        {
            0 => Build(U1, U1, Acl(4, Ace(9, 0, 16, U1, new byte[] { 1, 2, 3, 4 }))),
            1 => Build(U1, U1, Acl(4, Ace(0, 0x20, 16, U1))),
            2 => Build(U1, U1, Acl(4), AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(2, 0x40, 16, U1))),
            3 => Build(U1, U1, Acl(4), tail: new byte[] { 1, 2, 3, 4 }),
            4 => Build(U1, U1, Acl(4), extraControl: 0x40),
            _ => Build(U1, U1, Acl(4), sbz1: 7)
        };
        var wrapper = InteropWrapper(raw);
        var before = wrapper.Descriptor.MutationState;
        var called = false;
        var exception = Record.Exception(() => wrapper.ExportDetachedInterop((bytes, _, _) => { called = true; return bytes; }, bytes => bytes));
        Assert.True(exception is InvalidOperationException or NotSupportedException);
        Assert.False(called);
        Assert.Same(before, wrapper.Descriptor.MutationState);
        Assert.Equal(raw, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Fact]
    public void Interop_RepackedComponentsAreEquivalentButUnknownPaddingIsNot()
    {
        var wrapper = InteropWrapper(Build(U1, U2, Acl(4), Acl(4)));
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        var reordered = Build(U1, U2, Acl(4), Acl(4), order: new[] { Part.Dacl, Part.Sacl, Part.Group, Part.Owner });
        Assert.Equal(reordered, wrapper.ExportDetachedInterop((_, _, _) => reordered, bytes => bytes));
        var padded = Build(U1, U2, Acl(4), Acl(4), gapBefore: 4);
        Assert.Throws<NotSupportedException>(() => wrapper.ExportDetachedInterop((_, _, _) => padded, bytes => bytes));
    }

    [Fact]
    public void Interop_SnapshotRetainsPendingIntentAndOriginalReadSeparately()
    {
        var original = Build(U1, U1, Acl(4));
        var wrapper = InteropWrapper(original);
        wrapper.SetGroup(new SecurityIdentifier(U2, 0));
        var snapshot = wrapper.CaptureInteropSnapshot();
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        Assert.Equal(original, snapshot.Original);
        Assert.Equal(SecurityMasks.Group, snapshot.Pending);
        Assert.Equal(SecurityMasks.Group, wrapper.PendingWriteSections);
        Assert.Equal(new[] { false, true, false, false }, wrapper.Flags());
    }

    [Fact]
    public void Interop_ActualMicrosoftObjectEditsNeverFlowBack()
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        static System.Security.AccessControl.CommonSecurityDescriptor Construct(byte[] bytes, bool container, bool directory)
            => new(container, directory, bytes, 0);
        static byte[] Serialize(System.Security.AccessControl.CommonSecurityDescriptor native)
        { var bytes = new byte[native.BinaryLength]; native.GetBinaryForm(bytes, 0); return bytes; }
        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => wrapper.ExportDetachedInterop(Construct, Serialize));
            Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
            return;
        }
        var plain = wrapper.ExportDetachedInterop(Construct, Serialize);
        plain.Owner = new System.Security.Principal.SecurityIdentifier(U2, 0);
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        var export = wrapper.ExportDetachedInterop(Construct, Serialize);
        export.Owner = new System.Security.Principal.SecurityIdentifier(U2, 0);
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
        export.Group = new System.Security.Principal.SecurityIdentifier(U2, 0);
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetGroup(typeof(SecurityIdentifier)));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Interop_CallerLocksRefuseBeforeExternalCode(bool write)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        if (write) wrapper.EnterWrite(); else wrapper.EnterRead();
        try
        {
            Assert.Throws<InvalidOperationException>(() => wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes));
        }
        finally { if (write) wrapper.ExitWrite(); else wrapper.ExitRead(); }
        Assert.Equal(SecurityMasks.None, wrapper.PendingWriteSections);
    }

    [Fact]
    public void Portable_GroupEditAndOwnerRemovalPreserveAclState()
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4)));
        var export = wrapper.ExportDetachedInterop(InteropRoundTrip, bytes => bytes);
        wrapper.Descriptor.Owner = null;
        wrapper.SetGroup(new SecurityIdentifier(U2, 0));
        Assert.Null(wrapper.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(new SecurityIdentifier(U2, 0), wrapper.GetGroup(typeof(SecurityIdentifier)));
        Assert.Equal(new[] { false, true, false, false }, wrapper.Flags());
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Group, wrapper.PendingWriteSections);
    }
}
