#pragma warning disable CA1416
using System.Buffers.Binary;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using C = AdForLinux.DirectoryServices.Security.Core;
using P = AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static byte[] CompoundSid(uint rid)
    { var sid = (byte[])U1.Clone(); BinaryPrimitives.WriteUInt32LittleEndian(sid.AsSpan(sid.Length - 4), rid); return sid; }
    private static byte[] CompoundAce(bool audit, bool obj, byte[] sid, uint mask, byte extra = 0) => obj
        ? ObjAce(audit ? (byte)7 : (byte)5, (byte)((audit ? 0x40 : 0) | extra), mask, 1, G1, null, sid)
        : Ace(audit ? (byte)2 : (byte)0, (byte)((audit ? 0x40 : 0) | extra), mask, sid);
    private static byte[] CompoundAcl(bool audit, bool obj) => Acl(4,
        CompoundAce(audit, obj, CompoundSid(1005), 128, 8),
        CompoundAce(audit, obj, U1, 16, 4), CompoundAce(audit, obj, U2, 16),
        CompoundAce(audit, obj, CompoundSid(1003), 32, 4),
        CompoundAce(audit, obj, CompoundSid(1004), 16), CompoundAce(audit, obj, CompoundSid(1004), 32),
        CompoundAce(audit, obj, CompoundSid(1005), 16, 16));
    private static void CompoundAddPortable(FacadeContracts.Wrapper wrapper, bool audit, bool obj, byte[] sid)
    {
        var id = new P.SecurityIdentifier(sid, 0);
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, id, 16, 0, 0,
            obj ? ObjectAceFlags.ObjectAceTypePresent : ObjectAceFlags.None, obj ? G1 : Guid.Empty, Guid.Empty);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, id, 16, 0, 0,
            obj ? ObjectAceFlags.ObjectAceTypePresent : ObjectAceFlags.None, obj ? G1 : Guid.Empty, Guid.Empty);
    }
    private static byte[] CompoundMask(byte[] image, bool audit, byte[] sid, int mask)
    {
        if (OperatingSystem.IsWindows())
        {
            var raw = new RawSecurityDescriptor(image, 0); var acl = audit ? raw.SystemAcl! : raw.DiscretionaryAcl!;
            var id = new System.Security.Principal.SecurityIdentifier(sid, 0);
            foreach (GenericAce ace in acl) if (ace is KnownAce known && known.SecurityIdentifier.Equals(id)) known.AccessMask = mask;
            var result = new byte[raw.BinaryLength]; raw.GetBinaryForm(result, 0);
            return InteropRoundTrip(result, true, true);
        }
        var portable = new A.RawSecurityDescriptor(image, 0); var selected = audit ? portable.SystemAcl! : portable.DiscretionaryAcl!;
        var identity = new P.SecurityIdentifier(sid, 0);
        foreach (A.GenericAce ace in selected) if (ace is A.KnownAce known && known.SecurityIdentifier.Equals(identity)) known.AccessMask = mask;
        return InteropRoundTrip(A.FacadeMutation.Bytes(portable), true, true);
    }
    private static byte[] CompoundGroup(byte[] image, byte[] sid)
    {
        if (OperatingSystem.IsWindows())
        {
            var descriptor = new CommonSecurityDescriptor(true, true, image, 0) { Group = new System.Security.Principal.SecurityIdentifier(sid, 0) };
            var result = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(result, 0); return result;
        }
        var portable = new A.CommonSecurityDescriptor(true, true, image, 0) { Group = new P.SecurityIdentifier(sid, 0) };
        return A.FacadeMutation.Bytes(portable);
    }
    private static byte[] CompoundTarget(byte[] image, bool audit, bool obj, int mode)
    {
        if (mode != 1) image = CompoundMask(image, audit, U1, 32);
        if (mode >= 1) image = InteropRemoveUnique(image, audit, obj, U2, 16);
        if (mode == 3) image = InteropRemoveUnique(image, audit, obj, CompoundSid(1003), 32);
        image = InteropAddUnique(image, audit, obj, Everyone);
        if (mode == 2) image = InteropAddUnique(image, audit, obj, Admins);
        return image;
    }
    public static IEnumerable<object[]> CompoundInteropCases()
    {
        foreach (var audit in new[] { false, true }) foreach (var obj in new[] { false, true })
        foreach (var retained in new[] { false, true }) foreach (var mode in Enumerable.Range(0, 4))
            yield return new object[] { audit, obj, retained, mode };
    }
    [Theory]
    [MemberData(nameof(CompoundInteropCases))]
    public void InteropAcl_CompoundEditsUseOriginalContributorsAndPreserveRawSurvivors(bool audit, bool obj, bool retained, int mode)
    {
        var wrapper = InteropWrapper(Build(U1, U1, audit ? Acl(4) : CompoundAcl(false, obj), audit ? CompoundAcl(true, obj) : Acl(4)));
        if (retained) CompoundAddPortable(wrapper, audit, obj, CompoundSid(1006));
        wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        var peerDescriptor = new A.CommonSecurityDescriptor(true, true, wrapper.GetSecurityDescriptorBinaryForm(), 0);
        if (audit) peerDescriptor.SystemAcl = wrapper.Descriptor.SystemAcl;
        else peerDescriptor.DiscretionaryAcl = wrapper.Descriptor.DiscretionaryAcl;
        var peer = new FacadeContracts.Wrapper(peerDescriptor);
        var acl = audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl!;
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var before = C.SecurityDescriptor.Parse(export.Provenance.Snapshot.Raw, AllEntrySections);
        var original = (audit ? before.Sacl! : before.Dacl!).Aces;
        var target = CompoundTarget(export.Value, audit, obj, mode);
        var changed = wrapper.ReconcileInterop(export.Provenance, target);
        Assert.Equal(audit ? SecurityMasks.Sacl : SecurityMasks.Dacl, changed);
        var expected = new List<byte[]>();
        foreach (var ace in original)
        {
            var sid = ace.Sid!.ToArray();
            if ((mode >= 1 && sid.AsSpan().SequenceEqual(U2)) || (mode == 3 && sid.AsSpan().SequenceEqual(CompoundSid(1003)))) continue;
            var bytes = ace.RawBytes.ToArray();
            if (mode != 1 && sid.AsSpan().SequenceEqual(U1)) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 32);
            expected.Add(bytes);
        }
        var anchor = expected.FindIndex(bytes => C.Ace.Read(bytes).Sid!.ToArray().AsSpan().SequenceEqual(U1));
        expected.Insert(anchor, CompoundAce(audit, obj, Everyone, 16));
        if (mode == 2) expected.Insert(anchor + 1, CompoundAce(audit, obj, Admins, 16));
        Assert.Equal(Build(U2, U1, audit ? Acl(4) : Acl(4, expected.ToArray()), audit ? Acl(4, expected.ToArray()) : Acl(4)),
            wrapper.Descriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(target, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(target, peer.GetSecurityDescriptorBinaryForm());
        Assert.Same(acl, audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl!);
        Assert.Equal(SecurityMasks.Owner | changed, wrapper.PendingWriteSections);
        Assert.Equal(new[] { false, false, false, false }, peer.Flags()); Assert.True(acl.IsCanonical);
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, target));
        var next = InteropAddUnique(target, audit, obj, CompoundSid(1007));
        CompoundAddPortable(wrapper, audit, obj, CompoundSid(1007));
        Assert.Equal(next, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(next, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(before.GetBinaryForm(), export.Provenance.Snapshot.Raw);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_CompoundAllSectionsPublishTogether(bool obj)
    {
        var wrapper = InteropWrapper(Build(U1, U1, CompoundAcl(false, obj), CompoundAcl(true, obj)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = CompoundGroup(InteropOwner(CompoundTarget(CompoundTarget(export.Value, true, obj, 2), false, obj, 3), U2), Admins);
        Assert.Equal(AllEntrySections, wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Equal(candidate, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(AllEntrySections, wrapper.PendingWriteSections);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_CompoundSecondSectionFailureRestoresEverySharedOwner(bool obj)
    {
        var wrapper = InteropWrapper(Build(U1, U1, CompoundAcl(false, obj), CompoundAcl(true, obj)));
        wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        var peer = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, wrapper.GetSecurityDescriptorBinaryForm(), 0) { SystemAcl = wrapper.Descriptor.SystemAcl });
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var valid = CompoundTarget(export.Value, true, obj, 2);
        var invalid = CompoundGroup(InteropOwner(CompoundMask(valid, false, CompoundSid(1004), 64), U1), Admins); // merged original contributors
        var state = wrapper.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState; var flags = wrapper.Flags();
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, invalid));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(flags, wrapper.Flags()); Assert.Equal(SecurityMasks.Owner, wrapper.PendingWriteSections);
        Assert.Equal(SecurityMasks.Sacl, wrapper.ReconcileInterop(export.Provenance, valid));
        Assert.Equal(valid, peer.GetSecurityDescriptorBinaryForm());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_CompoundSharedOwnerLayoutFailureRollsBackFirstOwner(bool audit)
    {
        var initial = Build(U1, U1, CompoundAcl(false, false), CompoundAcl(true, false));
        var wrapper = InteropWrapper(initial);
        var peerDescriptor = new A.CommonSecurityDescriptor(true, true,
            Build(U1, U1, CompoundAcl(false, false), CompoundAcl(true, false), gapBefore: 4, tail: new byte[] { 9, 8, 7, 6 }), 0);
        if (audit) peerDescriptor.SystemAcl = wrapper.Descriptor.SystemAcl;
        else peerDescriptor.DiscretionaryAcl = wrapper.Descriptor.DiscretionaryAcl;
        var peer = new FacadeContracts.Wrapper(peerDescriptor);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = CompoundTarget(export.Value, audit, false, 2);
        var state = wrapper.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState;
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Equal(initial, state.Descriptor.GetBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags()); Assert.Equal(new[] { false, false, false, false }, peer.Flags());
    }

    [Theory]
    [InlineData(false, "replace")] [InlineData(true, "replace")]
    [InlineData(false, "split")] [InlineData(true, "split")]
    [InlineData(false, "merge")] [InlineData(true, "merge")]
    [InlineData(false, "inherited")] [InlineData(true, "inherited")]
    [InlineData(false, "opaque")] [InlineData(true, "opaque")]
    [InlineData(false, "noncanonical")] [InlineData(true, "noncanonical")]
    public void InteropAcl_CompoundUnprovenChangesRefuseWithoutReplacementIntent(bool audit, string change)
    {
        var wrapper = InteropWrapper(Build(U1, U1, CompoundAcl(false, false), CompoundAcl(true, false)));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var valid = CompoundTarget(export.Value, audit, false, 2);
        var raw = new A.RawSecurityDescriptor(valid, 0); var acl = audit ? raw.SystemAcl! : raw.DiscretionaryAcl!;
        if (change == "inherited") acl.RemoveAce(acl.Count - 1);
        else
        {
            A.GenericAce addition = change switch
            {
                "opaque" => A.GenericAce.CreateFromBinaryForm(new byte[] { 0x42, 0, 4, 0 }, 0),
                "replace" => new A.CommonAce(audit ? AceFlags.FailedAccess : 0, audit ? AceQualifier.SystemAudit : AceQualifier.AccessDenied, 64, new P.SecurityIdentifier(U2, 0), false, null),
                "split" => new A.CommonAce((audit ? AceFlags.SuccessfulAccess : 0) | AceFlags.ContainerInherit, audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed, 64, new P.SecurityIdentifier(U1, 0), false, null),
                "merge" => new A.CommonAce(audit ? AceFlags.SuccessfulAccess : 0, audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed, 64, new P.SecurityIdentifier(U1, 0), false, null),
                _ => new A.CommonAce(audit ? AceFlags.SuccessfulAccess : 0, audit ? AceQualifier.SystemAudit : AceQualifier.AccessDenied, 16, new P.SecurityIdentifier(CompoundSid(1008), 0), false, null)
            };
            acl.InsertAce(change == "noncanonical" ? acl.Count : 0, addition);
        }
        var candidate = A.FacadeMutation.Bytes(raw);
        // Canonicalize only supported candidates so refusals aren't masked by ordering.
        if (change is "replace" or "split") candidate = InteropRoundTrip(candidate, true, true);
        var state = wrapper.Descriptor.MutationState;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm());
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
    }
}
