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
    private static byte[] InteropAddUnique(byte[] image, bool audit, bool objectAce, byte[] sid, int mask = 16)
    {
        if (OperatingSystem.IsWindows())
        {
            var descriptor = new CommonSecurityDescriptor(true, true, image, 0);
            var identity = new System.Security.Principal.SecurityIdentifier(sid, 0);
            if (audit)
            {
                if (objectAce) descriptor.SystemAcl!.AddAudit(AuditFlags.Success, identity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
                else descriptor.SystemAcl!.AddAudit(AuditFlags.Success, identity, mask, 0, 0);
            }
            else
            {
                if (objectAce) descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, identity, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
                else descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, identity, mask, 0, 0);
            }
            var result = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(true, true, image, 0);
        var id = new P.SecurityIdentifier(sid, 0);
        if (audit)
        {
            if (objectAce) portable.SystemAcl!.AddAudit(AuditFlags.Success, id, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
            else portable.SystemAcl!.AddAudit(AuditFlags.Success, id, mask, 0, 0);
        }
        else
        {
            if (objectAce) portable.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, id, mask, 0, 0, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty);
            else portable.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, id, mask, 0, 0);
        }
        return A.FacadeMutation.Bytes(portable);
    }

    [Theory]
    [InlineData(false, false, 0)] [InlineData(false, false, 1)] [InlineData(false, false, 2)]
    [InlineData(false, true, 0)] [InlineData(false, true, 1)] [InlineData(false, true, 2)]
    [InlineData(true, false, 0)] [InlineData(true, false, 1)] [InlineData(true, false, 2)]
    [InlineData(true, true, 0)] [InlineData(true, true, 1)] [InlineData(true, true, 2)]
    public void InteropAcl_InsertionPreservesEveryRawSurvivorAndItsOrder(bool audit, bool objectAce, int position)
    {
        var identities = new[] { Everyone, U1, U2 };
        var oldIds = identities.Where((_, index) => index != position).ToArray();
        byte flags = audit ? (byte)0x40 : (byte)0;
        byte[] Make(byte extra, uint mask, byte[] sid) => objectAce
            ? ObjAce(audit ? (byte)7 : (byte)5, (byte)(flags | extra), mask, 1, G1, null, sid)
            : Ace(audit ? (byte)2 : (byte)0, (byte)(flags | extra), mask, sid);
        var original = new[] { Make(8, 128, Admins), Make(4, 16, oldIds[0]), Make(0, 32, oldIds[0]),
            Make(4, 32, oldIds[1]), Make(16, 16, U1) };
        var raw = Build(U1, U1, audit ? Acl(4) : Acl(4, original), audit ? Acl(4, original) : Acl(4));
        var wrapper = InteropWrapper(raw);
        var peer = new FacadeContracts.Wrapper(wrapper.Descriptor);
        var acl = audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl;
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(export.Value, audit, objectAce, identities[position]);
        Assert.Equal(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, wrapper.ReconcileInterop(export.Provenance, edited));
        var expected = original.ToList(); expected.Insert(position == 0 ? 1 : position == 1 ? 3 : 4, Make(0, 16, identities[position]));
        Assert.Equal(Build(U1, U1, audit ? Acl(4) : Acl(4, expected.ToArray()), audit ? Acl(4, expected.ToArray()) : Acl(4)),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(edited, peer.GetSecurityDescriptorBinaryForm());
        Assert.Same(acl, audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl);
        Assert.Equal(new[] { false, false, false, false }, peer.Flags());
        Assert.Equal(raw, export.Provenance.Snapshot.Raw);
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, edited));
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(false, 2)]
    [InlineData(true, 0)] [InlineData(true, 1)] [InlineData(true, 2)]
    public void InteropAcl_InsertionRetainsContributorStateAndPendingIntent(bool audit, int position)
    {
        var ids = new[] { Everyone, U1, U2 }; var old = ids.Where((_, i) => i != position).ToArray();
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : Acl(4, Ace(type, flags, 16, old[0])),
            audit ? Acl(4, Ace(type, flags, 16, old[0])) : Acl(4)));
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(old[1], 0), 16, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(old[1], 0), 16, 0, 0);
        wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        var peer = new FacadeContracts.Wrapper(wrapper.Descriptor);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(export.Value, audit, false, ids[position]);
        wrapper.ReconcileInterop(export.Provenance, edited);
        var aces = ids.Select(id => Ace(type, flags, 16, id)).ToArray();
        Assert.Equal(Build(U2, U1, audit ? Acl(4) : Acl(4, aces), audit ? Acl(4, aces) : Acl(4)),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Owner | (audit ? SecurityMasks.Sacl : SecurityMasks.Dacl), wrapper.PendingWriteSections);
        // Subsequent edit-back uses the newly inserted single contributor.
        var again = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var changed = InteropSetMask(again.Value, audit, ids[position], 32);
        wrapper.ReconcileInterop(again.Provenance, changed);
        Assert.Equal(changed, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(changed, peer.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_InsertionIntoPresentEmptyAclKeepsItsState(bool audit)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4), Acl(4)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(export.Value, audit, false, U1);
        wrapper.ReconcileInterop(export.Provenance, edited);
        Assert.Equal(C.AclState.Populated, audit ? wrapper.Descriptor.MutationState.Descriptor.SaclState : wrapper.Descriptor.MutationState.Descriptor.DaclState);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_MultipleInsertionsUseStableSurvivorAnchors(bool audit)
    {
        var wrapper = InteropWrapper(Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1))));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(InteropAddUnique(export.Value, audit, false, U2), audit, false, Everyone);
        wrapper.ReconcileInterop(export.Provenance, edited);
        Assert.Equal(edited, wrapper.GetSecurityDescriptorBinaryForm());
        var raw = audit ? wrapper.Descriptor.MutationState.Descriptor.Sacl! : wrapper.Descriptor.MutationState.Descriptor.Dacl!;
        Assert.Equal(new[] { Convert.ToHexString(Everyone), Convert.ToHexString(U1), Convert.ToHexString(U2) }, raw.Aces.Select(a => Convert.ToHexString(a.Sid!.ToArray())));
    }

    [Theory]
    [InlineData(false, "inherited")] [InlineData(true, "inherited")]
    [InlineData(false, "normalize")] [InlineData(true, "normalize")]
    [InlineData(false, "merge")] [InlineData(true, "merge")]
    [InlineData(false, "zero")] [InlineData(true, "zero")]
    [InlineData(false, "opaque")] [InlineData(true, "opaque")]
    [InlineData(false, "wrong-kind")] [InlineData(true, "wrong-kind")]
    [InlineData(false, "mask")] [InlineData(true, "mask")]
    [InlineData(false, "remove")] [InlineData(true, "remove")]
    [InlineData(false, "reorder")] [InlineData(true, "reorder")]
    [InlineData(false, "duplicate")] [InlineData(true, "duplicate")]
    public void InteropAcl_InsertionRefusesUnprovenChangesAtomically(bool audit, string change)
    {
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var originals = new[] { Ace(type, flags, 16, U1), Ace(type, flags, 32, U2) };
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : Acl(4, originals), audit ? Acl(4, originals) : Acl(4)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = originals.ToList();
        var added = change switch
        {
            "inherited" => Ace(type, (byte)(flags | 16), 16, Everyone),
            "normalize" => Ace(type, (byte)(flags | 4), 16, Everyone),
            "merge" => Ace(type, flags, 64, U1),
            "zero" => Ace(type, flags, 0, Everyone),
            "opaque" => new byte[] { 0x42, 0, 4, 0 },
            "wrong-kind" => Ace(audit ? (byte)0 : (byte)2, audit ? (byte)0 : (byte)0x40, 16, Everyone),
            _ => Ace(type, flags, 16, Everyone)
        };
        if (change == "mask") edited[0] = Ace(type, flags, 64, U1);
        if (change == "remove") { edited.RemoveAt(0); edited.Add(Ace(type, flags, 16, Admins)); }
        if (change == "reorder") edited.Reverse();
        edited.Insert(0, added);
        if (change == "duplicate") edited.Insert(0, added);
        var candidate = Build(U1, U1, audit ? Acl(4) : Acl(4, edited.ToArray()), audit ? Acl(4, edited.ToArray()) : Acl(4));
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(state, wrapper.Descriptor.MutationState);
        Assert.Equal(export.Provenance.Snapshot.Raw, state.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_InsertionRefusesBackwardRawAnchorsWithoutMovingSurvivors(bool audit)
    {
        var third = (byte[])U2.Clone(); third[^4]++;
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var raw = new[] { Ace(type, flags, 16, third), Ace(type, flags, 16, U1) };
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : Acl(4, raw), audit ? Acl(4, raw) : Acl(4)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(InteropAddUnique(export.Value, audit, false, Everyone), audit, false, U2);
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, edited));
        Assert.Same(state, wrapper.Descriptor.MutationState);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_InsertionRefusesRawCapacityOverflowWithoutDroppingHiddenOriginals(bool audit)
    {
        byte type = audit ? (byte)2 : (byte)0, flags = audit ? (byte)0x40 : (byte)0;
        var originals = Enumerable.Repeat(Ace(type, (byte)(flags | 8), 128, Everyone), 3274)
            .Append(Ace(type, flags, 16, U1)).ToArray();
        var raw = Build(U1, U1, audit ? Acl(4) : Acl(4, originals), audit ? Acl(4, originals) : Acl(4));
        var wrapper = InteropWrapper(raw); var peer = new FacadeContracts.Wrapper(wrapper.Descriptor);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropAddUnique(export.Value, audit, false, U2);
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, edited));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(state, peer.Descriptor.MutationState);
        Assert.Equal(raw, state.Descriptor.GetBinaryForm());
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }

    [Fact]
    public void InteropAcl_InsertionRollsBackSharedAclWhenAnotherSectionFails()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)), Acl(4, Ace(2, 0x40, 16, U1)));
        var wrapper = InteropWrapper(raw);
        var peer = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, raw, 0) { SystemAcl = wrapper.Descriptor.SystemAcl });
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var edited = InteropSetMask(InteropAddUnique(export.Value, true, false, U2), false, U1, 64);
        var state = wrapper.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, edited));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags()); Assert.Equal(new[] { false, false, false, false }, peer.Flags());
    }
}
