#pragma warning disable CA1416
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
    private static byte[] CanonicalInsertionBaseline(int kind, bool objectAce)
    {
        var audit = kind == 2;
        byte flags = (byte)((kind == 0 ? 0 : 16) | (audit ? 0x40 : 0));
        var ace = objectAce ? ObjAce(audit ? (byte)7 : (byte)5, flags, 16, 1, G1, null, U1)
            : Ace(audit ? (byte)2 : (byte)0, flags, 16, U1);
        return Build(U1, U1, audit ? Acl(4) : Acl(4, ace), audit ? Acl(4, ace) : Acl(4));
    }

    // Windows constructs the bad order through the real raw ACL API, then proves
    // that a newly constructed CommonSecurityDescriptor reports it noncanonical
    // and blocks mutation. Linux runs the same contract through portable objects.
    private static byte[] NoncanonicalInsertionTarget(byte[] baseline, int kind, bool objectAce)
    {
        var audit = kind == 2;
        var qualifier = audit ? AceQualifier.SystemAudit : kind == 0 ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed;
        var flags = audit ? AceFlags.SuccessfulAccess : AceFlags.None;
        if (OperatingSystem.IsWindows())
        {
            var raw = new RawSecurityDescriptor(baseline, 0);
            var acl = audit ? raw.SystemAcl! : raw.DiscretionaryAcl!;
            var sid = new System.Security.Principal.SecurityIdentifier(U2, 0);
            GenericAce added = objectAce ? new ObjectAce(flags, qualifier, 16, sid, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty, false, null)
                : new CommonAce(flags, qualifier, 16, sid, false, null);
            acl.InsertAce(acl.Count, added);
            var candidate = new byte[raw.BinaryLength]; raw.GetBinaryForm(candidate, 0);
            var imported = new CommonSecurityDescriptor(true, true, candidate, 0);
            Assert.False(audit ? imported.IsSystemAclCanonical : imported.IsDiscretionaryAclCanonical);
            var before = new byte[imported.BinaryLength]; imported.GetBinaryForm(before, 0);
            Assert.Equal(candidate, before);
            if (audit) Assert.Throws<InvalidOperationException>(() => imported.SystemAcl!.AddAudit(AuditFlags.Success, sid, 32, 0, 0));
            else Assert.Throws<InvalidOperationException>(() => imported.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, sid, 32, 0, 0));
            var after = new byte[imported.BinaryLength]; imported.GetBinaryForm(after, 0);
            Assert.Equal(before, after);
            return candidate;
        }
        var portable = new A.RawSecurityDescriptor(baseline, 0);
        var portableAcl = audit ? portable.SystemAcl! : portable.DiscretionaryAcl!;
        var identity = new P.SecurityIdentifier(U2, 0);
        A.GenericAce extra = objectAce ? new A.ObjectAce(flags, qualifier, 16, identity, ObjectAceFlags.ObjectAceTypePresent, G1, Guid.Empty, false, null)
            : new A.CommonAce(flags, qualifier, 16, identity, false, null);
        portableAcl.InsertAce(portableAcl.Count, extra);
        var bytes = A.FacadeMutation.Bytes(portable);
        var value = new A.CommonSecurityDescriptor(true, true, bytes, 0);
        Assert.False(audit ? value.IsSystemAclCanonical : value.IsDiscretionaryAclCanonical);
        Assert.Equal(bytes, A.FacadeMutation.Bytes(value));
        if (audit) Assert.Throws<InvalidOperationException>(() => value.SystemAcl!.AddAudit(AuditFlags.Success, identity, 32, 0, 0));
        else Assert.Throws<InvalidOperationException>(() => value.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, identity, 32, 0, 0));
        Assert.Equal(bytes, A.FacadeMutation.Bytes(value));
        return bytes;
    }

    [Theory]
    [InlineData(0, false, false)] [InlineData(0, false, true)]
    [InlineData(0, true, false)] [InlineData(0, true, true)]
    [InlineData(1, false, false)] [InlineData(1, false, true)]
    [InlineData(1, true, false)] [InlineData(1, true, true)]
    [InlineData(2, false, false)] [InlineData(2, false, true)]
    [InlineData(2, true, false)] [InlineData(2, true, true)]
    public void InteropAcl_NoncanonicalInsertionRefusesWithAliasesAndFutureMutationIntact(int kind, bool objectAce, bool retained)
    {
        var audit = kind == 2;
        var raw = CanonicalInsertionBaseline(kind, objectAce);
        var wrapper = InteropWrapper(raw);
        if (retained)
        {
            if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(Everyone, 0), 16, 0, 0);
            else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(Everyone, 0), 16, 0, 0);
        }
        var acl = audit ? (A.CommonAcl)wrapper.Descriptor.SystemAcl! : wrapper.Descriptor.DiscretionaryAcl!;
        var peerDescriptor = new A.CommonSecurityDescriptor(true, true, wrapper.GetSecurityDescriptorBinaryForm(), 0);
        if (audit) peerDescriptor.SystemAcl = wrapper.Descriptor.SystemAcl;
        else peerDescriptor.DiscretionaryAcl = wrapper.Descriptor.DiscretionaryAcl;
        var peer = new FacadeContracts.Wrapper(peerDescriptor);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = NoncanonicalInsertionTarget(export.Value, kind, objectAce);
        var state = wrapper.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState;
        var pending = wrapper.PendingWriteSections; var peerPending = peer.PendingWriteSections;
        var exception = Record.Exception(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.True(exception is NotSupportedException,
            $"Noncanonical candidate was accepted; cached facade canonicality is {acl.IsCanonical}, while fresh import reports false. Exception: {exception}");
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Same(acl, audit ? (A.CommonAcl)peer.Descriptor.SystemAcl! : peer.Descriptor.DiscretionaryAcl!);
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(pending, wrapper.PendingWriteSections); Assert.Equal(peerPending, peer.PendingWriteSections);
        Assert.True(acl.IsCanonical); Assert.True(audit ? wrapper.Descriptor.IsSystemAclCanonical : wrapper.Descriptor.IsDiscretionaryAclCanonical);
        Assert.Equal(new[] { false, false, false, false }, wrapper.Flags()); Assert.Equal(new[] { false, false, false, false }, peer.Flags());
        // A legitimate subsequent mutation must remain allowed and match actual Windows.
        var expected = InteropAddUnique(export.Value, audit, false, Admins);
        if (audit) wrapper.Descriptor.SystemAcl!.AddAudit(AuditFlags.Success, new P.SecurityIdentifier(Admins, 0), 16, 0, 0);
        else wrapper.Descriptor.DiscretionaryAcl!.AddAccess(AccessControlType.Allow, new P.SecurityIdentifier(Admins, 0), 16, 0, 0);
        Assert.Equal(expected, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(expected, peer.GetSecurityDescriptorBinaryForm());
        Assert.True(acl.IsCanonical);
        Assert.Throws<InvalidOperationException>(() => wrapper.ReconcileInterop(export.Provenance, export.Value));
    }

    [Theory]
    [InlineData(0, false)] [InlineData(0, true)] [InlineData(1, false)] [InlineData(1, true)]
    [InlineData(2, false)] [InlineData(2, true)]
    public void InteropAcl_CorePlannerRejectsNoncanonicalInsertion(int kind, bool objectAce)
    {
        var audit = kind == 2;
        var wrapper = InteropWrapper(CanonicalInsertionBaseline(kind, objectAce));
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = NoncanonicalInsertionTarget(export.Value, kind, objectAce);
        var before = C.SecurityDescriptor.Parse(export.Value, AllEntrySections);
        var after = C.SecurityDescriptor.Parse(candidate, AllEntrySections);
        var first = audit ? before.Sacl! : before.Dacl!; var second = audit ? after.Sacl! : after.Dacl!;
        Assert.Throws<NotSupportedException>(() => wrapper.Descriptor.MutationState.ReconcileInteropEdits(
            audit ? SecurityMasks.Sacl : SecurityMasks.Dacl,
            C.DescriptorRewriter.EncodeAcl(first, first.Aces), C.DescriptorRewriter.EncodeAcl(second, second.Aces)));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void InteropAcl_NoncanonicalSecondAclRollsBackInsertionAndSharedOwners(bool objectAce)
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1)));
        var wrapper = InteropWrapper(raw); wrapper.SetOwner(new P.SecurityIdentifier(U2, 0));
        var peerDescriptor = new A.CommonSecurityDescriptor(true, true, wrapper.GetSecurityDescriptorBinaryForm(), 0) { SystemAcl = wrapper.Descriptor.SystemAcl };
        var peer = new FacadeContracts.Wrapper(peerDescriptor);
        var export = wrapper.ExportInterop(InteropRoundTrip, bytes => bytes);
        var candidate = NoncanonicalInsertionTarget(InteropAddUnique(export.Value, true, false, U2), 0, objectAce);
        var state = wrapper.Descriptor.MutationState; var peerState = peer.Descriptor.MutationState;
        var flags = wrapper.Flags(); var pending = wrapper.PendingWriteSections;
        var acl = wrapper.Descriptor.SystemAcl;
        Assert.Throws<NotSupportedException>(() => wrapper.ReconcileInterop(export.Provenance, candidate));
        Assert.Same(state, wrapper.Descriptor.MutationState); Assert.Same(peerState, peer.Descriptor.MutationState);
        Assert.Same(acl, wrapper.Descriptor.SystemAcl); Assert.Same(acl, peer.Descriptor.SystemAcl);
        Assert.Equal(export.Value, wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(export.Value, peer.GetSecurityDescriptorBinaryForm());
        Assert.Equal(flags, wrapper.Flags()); Assert.Equal(pending, wrapper.PendingWriteSections);
        Assert.True(wrapper.Descriptor.IsDiscretionaryAclCanonical); Assert.True(wrapper.Descriptor.IsSystemAclCanonical);
        // Rollback restored the original provenance too: a corrected candidate remains usable.
        var valid = InteropAddUnique(export.Value, true, false, U2);
        Assert.Equal(SecurityMasks.Sacl, wrapper.ReconcileInterop(export.Provenance, valid));
        Assert.Equal(valid, peer.GetSecurityDescriptorBinaryForm());
    }
}
