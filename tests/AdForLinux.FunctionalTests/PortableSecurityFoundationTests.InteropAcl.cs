#pragma warning disable CA1416
using System.Buffers.Binary;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
using C = AdForLinux.DirectoryServices.Security.Core;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static byte[] InteropSetMask(byte[] image, bool audit, byte[] sid, int mask)
    {
        if (OperatingSystem.IsWindows())
        {
            var native = new CommonSecurityDescriptor(true, true, image, 0);
            if (audit) native.SystemAcl!.SetAudit(AuditFlags.Success, new System.Security.Principal.SecurityIdentifier(sid, 0), mask, 0, 0);
            else native.DiscretionaryAcl!.SetAccess(AccessControlType.Allow, new System.Security.Principal.SecurityIdentifier(sid, 0), mask, 0, 0);
            var result = new byte[native.BinaryLength]; native.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(true, true, image, 0);
        if (audit) portable.SystemAcl!.SetAudit(AuditFlags.Success, new P.SecurityIdentifier(sid, 0), mask, 0, 0);
        else portable.DiscretionaryAcl!.SetAccess(AccessControlType.Allow, new P.SecurityIdentifier(sid, 0), mask, 0, 0);
        return A.FacadeMutation.Bytes(portable);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)] [InlineData(true, false)] [InlineData(true, true)]
    public void InteropAcl_UniqueMaskEditPreservesInactiveAndUnrelatedMergedOriginals(bool audit, bool shared)
    {
        byte type = audit ? (byte)2 : (byte)0; byte flags = audit ? (byte)0x40 : (byte)0;
        var aces = new[] { Ace(type, (byte)(flags | 8), 128, U2), Ace(type, flags, 16, U1),
            Ace(type, flags, 32, U1), Ace(type, (byte)(flags | 4), 16, U2) };
        var raw = Build(U1, U1, audit ? Acl(4) : Acl(4, aces), audit ? Acl(4, aces) : Acl(4, Ace(2, 0xC0, 64, U1)));
        var wrapper = InteropWrapper(raw);
        var other = shared ? new FacadeContracts.Wrapper(wrapper.Descriptor) : null;
        var acl = audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl;
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropSetMask(export.Value, audit, U2, 64);
        Assert.Equal(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, wrapper.ReconcileInterop(export.Provenance, edited));
        Assert.Same(acl, audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
        aces[3] = Ace(type, (byte)(flags | 4), 64, U2);
        var expected = Build(U1, U1, audit ? Acl(4) : Acl(4, aces), audit ? Acl(4, aces) : Acl(4, Ace(2, 0xC0, 64, U1)));
        Assert.Equal(expected, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(raw, export.Provenance.Snapshot.Raw);
        if (other is not null)
        {
            Assert.Equal(edited, other.GetSecurityDescriptorBinaryForm());
            Assert.Equal(new[] { false, false, false, false }, other.Flags());
        }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_RetainedContributorStateSupportsUniqueMaskEdit(bool audit)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1))));
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(U2, 0), 16, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(U2, 0), 16, 0, 0);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropSetMask(export.Value, audit, U2, 32);
        wrapper.ReconcileInterop(export.Provenance, edited);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
        // A subsequent live mutation must still validate retained provenance.
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(U2, 0), 64, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(U2, 0), 64, 0, 0);
        Assert.NotEqual(edited, wrapper.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void InteropAcl_AmbiguousOrStructuralDiffsRefuseAtomically(int variant)
    {
        var acl = variant switch
        {
            0 => Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)), // merged contributors
            1 => Acl(4, Ace(0, 0x10, 16, U1)), // inherited occurrence
            _ => Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U2))
        };
        var wrapper = InteropWrapper(Build(U1, U1, acl));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = export.Value.ToArray();
        var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(candidate.AsSpan(16)) + 8;
        if (variant == 3) candidate[offset + 1] |= 1; // scope change
        else if (variant == 4) candidate[offset] = 1; // qualifier change
        else BinaryPrimitives.WriteUInt32LittleEndian(candidate.AsSpan(offset + 4), variant == 2 ? 0u : 128u);
        var before = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(before, wrapper.Descriptor.MutationState);
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Fact]
    public void InteropAcl_FailureInSecondAclRollsBackFirstAclAndAllSharedOwners()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)), Acl(4, Ace(2, 0x40, 16, U2)));
        var first = InteropWrapper(raw);
        var peerDescriptor = new A.CommonSecurityDescriptor(true, true, raw, 0) { SystemAcl = first.Descriptor.SystemAcl };
        var peer = new FacadeContracts.Wrapper(peerDescriptor);
        var export = first.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = InteropSetMask(InteropSetMask(export.Value, true, U2, 32), false, U1, 64);
        var beforeFirst = first.Descriptor.MutationState; var beforePeer = peer.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => first.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(beforeFirst, first.Descriptor.MutationState); Assert.Same(beforePeer, peer.Descriptor.MutationState);
        Assert.Equal(export.Value, first.GetSecurityDescriptorBinaryForm());
        Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, first.Flags());
        Assert.Equal(new[] { false, false, false, false }, peer.Flags());
    }

    [Fact]
    public void InteropAcl_UnrelatedOpaqueAuditDataRefusesExportWithoutMutation()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(13, 0x40, 16, U1, new byte[] { 1, 2, 3, 4 })));
        var wrapper = InteropWrapper(raw);
        Assert.Throws<InvalidOperationException>(() => wrapper.ExportInterop(InteropRoundTrip, bytes => bytes));
        Assert.Equal(raw, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
    }
}
