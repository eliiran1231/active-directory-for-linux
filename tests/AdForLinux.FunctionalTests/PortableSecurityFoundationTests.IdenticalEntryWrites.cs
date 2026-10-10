#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using AdForLinux.Tests.Shared;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(false,false)] [InlineData(false,true)]
    [InlineData(true,false)] [InlineData(true,true)]
    public void Entry_identical_NULL_absent_reassignment_sends_no_extra_mask_then_real_shared_edit_writes_only_target(bool audit,bool priorOwner)
    {
        using var fixture = new EntryWriteFixture();fixture.Raw = IdenticalAssignmentCases.Baseline(audit);
        var original = (byte[])fixture.Raw.Clone();var source = fixture.Entry.ObjectSecurity;
        Assert.Equal(original,source.CaptureInteropSnapshot().Raw);
        if (priorOwner) source.SetOwner(new SecurityIdentifier(U2,0));
        var before = source.CaptureInteropSnapshot();
        var supplied = before.Raw;var suppliedCopy = (byte[])supplied.Clone();
        source.SetSecurityDescriptorBinaryForm(supplied,AccessControlSections.All);Assert.Equal(suppliedCopy,supplied);
        Assert.Equal(before.Raw,source.CaptureInteropSnapshot().Raw);
        Assert.Equal(before.Generation,source.CaptureInteropSnapshot().Generation);
        Assert.Equal(priorOwner ? EntryMasks.Owner : EntryMasks.None,source.PendingWriteSections);
        fixture.Entry.ObjectSecurity = source;Assert.Same(source,fixture.Entry.ObjectSecurity);
        fixture.Entry.CommitChanges();
        if (priorOwner)
        {
            var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
            AssertIdenticalWrite(request,EntryMasks.Owner,before.Raw);
            fixture.Raw = (byte[])before.Raw.Clone(); // Fake server readback of exactly the captured request.
        }
        else Assert.Empty(fixture.Writes);
        fixture.Writes.Clear();
        var fresh = fixture.Entry.ObjectSecurity;Assert.NotSame(source,fresh);
        Assert.Equal(EntryMasks.None,fresh.PendingWriteSections);
        var descriptor = fresh._securityDescriptor;
        var peer = new ActiveDirectorySecurity(descriptor,AllEntrySections);
        var alias = IdenticalAlias(descriptor);var aliasBefore = StateBoundary.Take(alias);
        var editBefore = fresh.CaptureInteropSnapshot();
        fresh.SetSecurityDescriptorBinaryForm(editBefore.Raw,AccessControlSections.All);
        Assert.Equal(editBefore.Generation,fresh.CaptureInteropSnapshot().Generation);
        Assert.Equal(EntryMasks.None,fresh.PendingWriteSections);
        IdenticalAssignmentCases.EditAcl(peer,audit); // Public rule API through the shared descriptor.
        var after = fresh.CaptureInteropSnapshot();
        Assert.True(after.Generation > editBefore.Generation);
        Assert.Equal(IdenticalAssignmentCases.Target(audit),fresh.PendingWriteSections);
        Assert.Equal(peer.GetSecurityDescriptorBinaryForm(),fresh.GetSecurityDescriptorBinaryForm());
        aliasBefore.Check(AccessControlSections.None,true,false);
        AssertUnselectedIdenticalBytes(editBefore.Raw,after.Raw,audit);
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)),IdenticalAssignmentCases.Target(audit),after.Raw);

    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_failed_compound_after_identical_assignment_restores_aliases_and_preserves_owner_plus_real_acl_write(bool audit)
    {
        using var fixture = new EntryWriteFixture();fixture.Raw = IdenticalAssignmentCases.Baseline(audit,true);
        var source = fixture.Entry.ObjectSecurity;Assert.Equal(fixture.Raw,source.CaptureInteropSnapshot().Raw);
        var peer = new ActiveDirectorySecurity(source._securityDescriptor,AllEntrySections);
        var alias = IdenticalAlias(source._securityDescriptor);var aliasBefore = StateBoundary.Take(alias);
        source.SetOwner(new SecurityIdentifier(U2,0));
        var identical = source.CaptureInteropSnapshot();
        source.SetSecurityDescriptorBinaryForm(identical.Raw,AccessControlSections.All);
        Assert.Equal(identical.Generation,source.CaptureInteropSnapshot().Generation);
        var states = new A.ObjectSecurity[] {source,peer,alias}.Select(StateBoundary.Take).ToArray();
        var binding = source.CaptureIdentityRead();var origin = source.RawReadOrigin;
        var supplied = IdenticalAssignmentCases.CompoundReplacement();var suppliedCopy = (byte[])supplied.Clone();
        Assert.Throws<InvalidOperationException>(() => source.SetSecurityDescriptorBinaryForm(supplied,AccessControlSections.All));
        AssertBoundRollback(states[0]);
        foreach (var state in states.Skip(1)) state.Check(AccessControlSections.None,false,false);
        Assert.Same(binding.Resolver,source.CaptureIdentityRead().Resolver);Assert.Same(origin,source.RawReadOrigin);
        Assert.Equal(suppliedCopy,supplied);Assert.Equal(EntryMasks.Owner,source.PendingWriteSections);
        IdenticalAssignmentCases.EditAcl(peer,audit);
        var after = source.CaptureInteropSnapshot();Assert.True(after.Generation > identical.Generation);
        Assert.Equal(EntryMasks.Owner | IdenticalAssignmentCases.Target(audit),source.PendingWriteSections);
        Assert.Equal(peer.GetSecurityDescriptorBinaryForm(),source.GetSecurityDescriptorBinaryForm());
        aliasBefore.Check(AccessControlSections.None,true,false);
        AssertUnselectedIdenticalBytes(identical.Raw,after.Raw,audit);
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)),EntryMasks.Owner | IdenticalAssignmentCases.Target(audit),after.Raw);
    }
    private static void AssertBoundRollback(StateBoundary before)
    {
        var source = before.Wrapper;var now = source.CaptureInteropSnapshot();var descriptor = source._securityDescriptor;
        Assert.True(source.HasRawReadContext);Assert.NotNull(source.CaptureIdentityRead().Resolver);
        Assert.Same(before.Descriptor,descriptor);Assert.Same(before.Engine,descriptor.MutationState);
        Assert.Same(before.Dacl,descriptor.DiscretionaryAcl);Assert.Same(before.Sacl,descriptor.SystemAcl);
        Assert.Same(before.DaclProvenance,descriptor.DiscretionaryAcl?.RetainedMutation);
        Assert.Same(before.SaclProvenance,descriptor.SystemAcl?.RetainedMutation);
        Assert.Equal(before.Snapshot.Raw,now.Raw);Assert.Equal(before.Snapshot.Observable,now.Observable);
        Assert.Equal(before.Snapshot.Original,now.Original);Assert.Equal(before.Snapshot.Generation,now.Generation);
        Assert.Equal(before.Snapshot.Source,now.Source);Assert.Equal(before.Snapshot.Attachment,now.Attachment);
        Assert.Equal(before.Snapshot.Retrieved,now.Retrieved);Assert.Equal(before.ReadVersion,source.ReadVersion);
        Assert.Equal(before.Intent,descriptor.MutationState.WriteIntent);Assert.Equal(before.Snapshot.Pending,now.Pending);
        Assert.Equal(before.Assignment,source.AssignmentSections);
    }
    private static FacadeContracts.Wrapper IdenticalAlias(A.CommonSecurityDescriptor d) => new(new A.CommonSecurityDescriptor(true,true,
        d.ControlFlags,d.Owner,d.Group,d.SystemAcl,d.DiscretionaryAcl));
    private static void AssertIdenticalWrite(ModifyRequest request,EntryMasks mask,byte[] expected)
    {
        Assert.Equal("CN=item,DC=example,DC=com",request.DistinguishedName);
        var modification = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("nTSecurityDescriptor",modification.Name);Assert.Equal(DirectoryAttributeOperation.Replace,modification.Operation);
        Assert.Equal(expected,Assert.IsType<byte[]>(Assert.Single(modification.Cast<object>())));
        Assert.Equal((System.DirectoryServices.Protocols.SecurityMasks)(int)mask,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
    }
    private static void AssertUnselectedIdenticalBytes(byte[] before,byte[] after,bool audit)
    {
        foreach (var field in new[] {4,8,audit ? 16 : 12}) Assert.Equal(ReplacementComponent(before,field),ReplacementComponent(after,field));
        var delta = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(before.AsSpan(2))
            ^ System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(after.AsSpan(2));
        Assert.Equal(0,delta & (audit ? ~0x2a10 : ~0x1504));
    }
}
