#pragma warning disable CA1416
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
    private static byte[] InteropRemoveUnique(byte[] image, bool audit, bool objectAce, byte[] sid, int mask)
    {
        if (OperatingSystem.IsWindows())
        {
            var descriptor = new CommonSecurityDescriptor(true, true, image, 0);
            var identity = new System.Security.Principal.SecurityIdentifier(sid, 0);
            if (audit)
            {
                if (objectAce) descriptor.SystemAcl!.RemoveAuditSpecific(AuditFlags.Success, identity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
                else descriptor.SystemAcl!.RemoveAuditSpecific(AuditFlags.Success, identity, mask, 0, 0);
            }
            else
            {
                if (objectAce) descriptor.DiscretionaryAcl!.RemoveAccessSpecific(AccessControlType.Allow, identity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
                else descriptor.DiscretionaryAcl!.RemoveAccessSpecific(AccessControlType.Allow, identity, mask, 0, 0);
            }
            var result = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(true, true, image, 0);
        var portableIdentity = new P.SecurityIdentifier(sid, 0);
        if (audit)
        {
            if (objectAce) portable.SystemAcl!.RemoveAuditSpecific(AuditFlags.Success, portableIdentity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
            else portable.SystemAcl!.RemoveAuditSpecific(AuditFlags.Success, portableIdentity, mask, 0, 0);
        }
        else
        {
            if (objectAce) portable.DiscretionaryAcl!.RemoveAccessSpecific(AccessControlType.Allow, portableIdentity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
            else portable.DiscretionaryAcl!.RemoveAccessSpecific(AccessControlType.Allow, portableIdentity, mask, 0, 0);
        }
        return A.FacadeMutation.Bytes(portable);
    }

    [Theory]
    [InlineData(false, false, false)] [InlineData(false, false, true)]
    [InlineData(false, true, false)] [InlineData(false, true, true)]
    [InlineData(true, false, false)] [InlineData(true, false, true)]
    [InlineData(true, true, false)] [InlineData(true, true, true)]
    public void InteropAcl_UniqueDeletionPreservesInactiveMergedAndOtherSectionBytes(bool audit, bool objectAce, bool shared)
    {
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var originals = new[] { Ace(type, (byte)(flags | 8), 128, Everyone),
            Ace(type, flags, 16, U1), Ace(type, flags, 32, U1),
            objectAce ? ObjAce(audit ? (byte)7 : (byte)5, (byte)(flags | 4), 16, 1, G1, null, U2)
                : Ace(type, (byte)(flags | 4), 16, U2) };
        var raw = Build(U1, U1, audit ? Acl(4) : Acl(4, originals), audit ? Acl(4, originals) : Acl(4));
        var wrapper = InteropWrapper(raw);
        var peer = shared ? new FacadeContracts.Wrapper(wrapper.Descriptor) : null;
        var acl = audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl;
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropRemoveUnique(export.Value, audit, objectAce, U2, 16);
        Assert.NotEqual(export.Value, edited);
        Assert.Equal(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, wrapper.ReconcileInterop(export.Provenance, edited));
        Assert.Same(acl, audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
        var survivors = originals.Take(3).ToArray();
        Assert.Equal(Build(U1, U1, audit ? Acl(4) : Acl(4, survivors), audit ? Acl(4, survivors) : Acl(4)),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(raw, export.Provenance.Snapshot.Raw);
        Assert.Equal(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, wrapper.PendingWriteSections);
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, edited));
        if (peer is not null)
        {
            Assert.Equal(edited, peer.GetSecurityDescriptorBinaryForm());
            Assert.Equal(new[] { false, false, false, false }, peer.Flags());
        }
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)] [InlineData(true, false)] [InlineData(true, true)]
    public void InteropAcl_DeletionRetainsContributorStateAndExistingOwnerIntent(bool audit, bool shared)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1))));
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(U2, 0), 16, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(U2, 0), 16, 0, 0);
        wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        var peer = shared ? new FacadeContracts.Wrapper(wrapper.Descriptor) : null;
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropRemoveUnique(export.Value, audit, false, U2, 16);
        wrapper.ReconcileInterop(export.Provenance, edited);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(SecurityMasks.Owner | (audit ? SecurityMasks.Sacl : SecurityMasks.Dacl), wrapper.PendingWriteSections);
        Assert.Equal(Build(U2, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1))),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        // Follow-on mutation must validate surviving contributor indices, including shared owners.
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(Everyone, 0), 32, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(Everyone, 0), 32, 0, 0);
        if (peer is not null) Assert.Equal(wrapper.GetSecurityDescriptorBinaryForm(), peer.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_DeletingLastExplicitOccurrencePreservesPresentEmptyAcl(bool audit)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4, Ace(0, 0, 16, U2)), Acl(4, Ace(2, 0x40, 16, U2))));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropRemoveUnique(export.Value, audit, false, U2, 16);
        wrapper.ReconcileInterop(export.Provenance, edited);
        var raw = wrapper.Descriptor.MutationState.Descriptor;
        Assert.Equal(C.AclState.Empty, audit ? raw.SaclState : raw.DaclState);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(false, "merged")] [InlineData(true, "merged")]
    [InlineData(false, "inherited")] [InlineData(true, "inherited")]
    [InlineData(false, "inherited-addition")] [InlineData(true, "inherited-addition")]
    [InlineData(false, "reorder")] [InlineData(true, "reorder")]
    [InlineData(false, "ambiguous")] [InlineData(true, "ambiguous")]
    public void InteropAcl_UnprovenStructuralEditsStillRefuseAtomically(bool audit, string kind)
    {
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var source = kind switch
        {
            "merged" => new[] { Ace(type, flags, 16, U1), Ace(type, flags, 32, U1) },
            "ambiguous" => new[] { Ace(type, flags, 16, U1), Ace(type, flags, 32, U1), Ace(type, flags, 64, U1) },
            "inherited" => new[] { Ace(type, (byte)(flags | 16), 16, U1) },
            _ => new[] { Ace(type, flags, 16, U1), Ace(type, flags, 32, U2) }
        };
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : Acl(4, source), audit ? Acl(4, source) : Acl(4)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var parsed = C.SecurityDescriptor.Parse(export.Value, AllEntrySections);
        var aces = (audit ? parsed.Sacl! : parsed.Dacl!).Aces.Select(a => a.RawBytes.ToArray()).ToList();
        if (kind == "inherited-addition") aces.Add(Ace(type, (byte)(flags | 16), 64, Everyone));
        else if (kind == "reorder") aces.Reverse();
        else aces.RemoveAt(0);
        var candidate = Build(U1, U1, audit ? Acl(4) : Acl(4, aces.ToArray()), audit ? Acl(4, aces.ToArray()) : Acl(4));
        var before = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(before, wrapper.Descriptor.MutationState);
        Assert.Equal(export.Provenance.Snapshot.Raw, wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(false, 2)]
    [InlineData(true, 0)] [InlineData(true, 1)] [InlineData(true, 2)]
    public void InteropAcl_DeletionAndMaskEditMapOriginalIndicesAcrossEveryPosition(bool audit, int position)
    {
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var identities = new[] { Everyone, U1, U2 };
        var originals = identities.Select(sid => Ace(type, (byte)(flags | 4), 16, sid)).ToArray();
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : Acl(4, originals), audit ? Acl(4, originals) : Acl(4)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var changedIndex = (position + 1) % 3;
        var edited = InteropSetMask(InteropRemoveUnique(export.Value, audit, false, identities[position], 16), audit, identities[changedIndex], 32);
        wrapper.ReconcileInterop(export.Provenance, edited);
        originals[changedIndex] = Ace(type, (byte)(flags | 4), 32, identities[changedIndex]);
        var survivors = originals.Where((_, index) => index != position).ToArray();
        Assert.Equal(Build(U1, U1, audit ? Acl(4) : Acl(4, survivors), audit ? Acl(4, survivors) : Acl(4)),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
    }

    [Fact]
    public void InteropAcl_LaterFailureRollsBackDeletionInSharedAcl()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)), Acl(4, Ace(2, 0x40, 16, U2)));
        var first = InteropWrapper(raw);
        var peer = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, raw, 0) { SystemAcl = first.Descriptor.SystemAcl });
        var export = first.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropSetMask(InteropRemoveUnique(export.Value, true, false, U2, 16), false, U1, 64);
        var firstState = first.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => first.ReconcileInterop(export.Provenance, edited));
        Assert.Same(firstState, first.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Equal(export.Value, first.GetSecurityDescriptorBinaryForm()); Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, first.Flags());
    }
}
