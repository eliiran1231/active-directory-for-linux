#pragma warning disable CA1416
using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using AdForLinux.Tests.Shared;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Contained_acl_reserved_byte_cannot_move_during_public_owner_shrink()
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = ContainedAclImage(true, 0xA5);
        var source = fixture.Entry.ObjectSecurity;
        var before = StateBoundary.Take(source);
        var error = Record.Exception(() => source.SetOwner(new SecurityIdentifier(Everyone, 0)));
        var after = source.CaptureInteropSnapshot();
        Assert.True(error is InvalidOperationException,
            $"Expected atomic refusal; actual error={error?.GetType().Name ?? "none"}, SACL offset={BinaryPrimitives.ReadUInt32LittleEndian(after.Raw.AsSpan(12))}, byte33={after.Raw[33]:X2}, byte57={after.Raw[57]:X2}, generation={before.Snapshot.Generation}->{after.Generation}");
        AssertBoundRollback(before);
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Unaligned_suffix_alias_padding_refuses_before_publication_or_commit()
    {
        using var fixture = new EntryWriteFixture();
        var raw = LayoutRelocationCases.PrefixGap(Build(U2, U2, Acl(4, Ace(0, 0, 16, U1)),
            Acl(4, Ace(2, 64, 16, U1), Ace(2, 64, 16, U2))), 3, 0xA5);
        var dacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4), (uint)(dacl + 16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), (uint)(dacl + 16));
        fixture.Raw = raw;
        var source = fixture.Entry.ObjectSecurity;
        var before = StateBoundary.Take(source);
        var error = Record.Exception(() => source.RemoveAuditRuleSpecific(new ActiveDirectoryAuditRule(
            new SecurityIdentifier(U2, 0), ActiveDirectoryRights.ReadProperty, AuditFlags.Success)));
        var after = source.CaptureInteropSnapshot();
        // Before the correction mutation succeeds, then CommitChanges refuses new
        // unscoped padding. The corrected boundary must refuse before publication.
        var commitError = error is null ? Record.Exception(fixture.Entry.CommitChanges) : null;
        Assert.True(error is InvalidOperationException,
            $"Expected early refusal; mutation={error?.GetType().Name ?? "none"}, commit={commitError?.Message ?? "none"}, length={raw.Length}->{after.Raw.Length}, generation={before.Snapshot.Generation}->{after.Generation}");
        AssertBoundRollback(before);
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }

    private static byte[] ContainedAclImage(bool sacl, byte reserved)
    {
        // Exactly 72 bytes: gap20..23, owner24..51, group52..63,
        // independent ACL64..71, and an ACL alias32..39 within the owner SID.
        var raw = LayoutRelocationCases.PrefixGap(Build(U1, Everyone, sacl ? Acl(4) : null,
            sacl ? null : Acl(4)), 4, 0xEE);
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(2), 0x8014);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(sacl ? 12 : 16), 32);
        new byte[] { 4, reserved, 8, 0, 0, 0, 0, 0 }.CopyTo(raw, 32);
        return raw;
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Contained_acl_refusal_preserves_peers_and_unrelated_pending_property(bool sacl, bool priorProperty)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = ContainedAclImage(sacl, 0xA5);
        var source = fixture.Entry.ObjectSecurity;
        var peer = new ActiveDirectorySecurity(source._securityDescriptor, AllEntrySections);
        var alias = IdenticalAlias(source._securityDescriptor);
        if (priorProperty) fixture.Entry.Properties["description"].Value = "pending";
        var before = StateBoundary.Take(source);
        var others = new[] { StateBoundary.Take(peer), StateBoundary.Take(alias) };
        Assert.Throws<InvalidOperationException>(() => peer.SetOwner(new SecurityIdentifier(Everyone, 0)));
        AssertBoundRollback(before);
        foreach (var state in others) state.Check(AccessControlSections.None, false, false);
        fixture.Entry.CommitChanges();
        if (!priorProperty) Assert.Empty(fixture.Writes);
        else
        {
            var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
            var change = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
            Assert.Equal("description", change.Name);
            Assert.Equal("pending", Assert.Single(change.Cast<object>()));
            Assert.DoesNotContain(request.Controls.Cast<DirectoryControl>(), c => c is SecurityDescriptorFlagControl);
        }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Clean_contained_acl_can_move_and_persist_exact_owner_change(bool sacl)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = ContainedAclImage(sacl, 0);
        var source = fixture.Entry.ObjectSecurity;
        var before = source.CaptureInteropSnapshot();
        source.SetOwner(new SecurityIdentifier(Everyone, 0));
        var after = source.CaptureInteropSnapshot();
        Assert.Equal(56u, BinaryPrimitives.ReadUInt32LittleEndian(after.Raw.AsSpan(sacl ? 12 : 16)));
        Assert.Equal(64, after.Raw.Length);
        Assert.Equal(before.Raw.AsSpan(20, 4).ToArray(), after.Raw.AsSpan(20, 4).ToArray());
        Assert.Equal(before.Raw, after.Original);
        Assert.Equal(before.Generation + 1, after.Generation);
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)),
            AdForLinux.DirectoryServices.SecurityMasks.Owner, after.Raw);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Bound_same_size_identity_alias_padding_refuses_atomically_with_pending_property(bool group, bool throughPeer)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = SameSizeAliasImage(group, 3);
        var source = fixture.Entry.ObjectSecurity;
        var peer = new ActiveDirectorySecurity(source._securityDescriptor, AllEntrySections);
        var alias = IdenticalAlias(source._securityDescriptor);
        fixture.Entry.Properties["description"].Value = "pending";
        // An explicit identical identity setter records wrapper assignment intent
        // without rewriting raw storage or adding a net security change.
        if (group) source.SetGroup(source.GetGroup(typeof(SecurityIdentifier))!);
        else source.SetOwner(source.GetOwner(typeof(SecurityIdentifier))!);
        var before = StateBoundary.Take(source);
        Assert.NotEqual(AdForLinux.DirectoryServices.SecurityMasks.None, before.Assignment);
        var others = new[] { StateBoundary.Take(peer), StateBoundary.Take(alias) };
        var target = throughPeer ? peer : source;
        var error = Record.Exception(() =>
        {
            if (group) target.SetGroup(new SecurityIdentifier(U2, 0));
            else target.SetOwner(new SecurityIdentifier(U2, 0));
        });
        var after = source.CaptureInteropSnapshot();
        var commitError = error is null ? Record.Exception(fixture.Entry.CommitChanges) : null;
        Assert.True(error is InvalidOperationException,
            $"Expected atomic refusal; mutation={error?.GetType().Name ?? "none"}, commit={commitError?.Message ?? "none"}, length={before.Snapshot.Raw.Length}->{after.Raw.Length}, generation={before.Snapshot.Generation}->{after.Generation}");
        AssertBoundRollback(before);
        foreach (var state in others) state.Check(AccessControlSections.None, false, false);
        fixture.Entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        var change = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("description", change.Name);
        Assert.Equal("pending", Assert.Single(change.Cast<object>()));
        Assert.DoesNotContain(request.Controls.Cast<DirectoryControl>(), c => c is SecurityDescriptorFlagControl);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Bound_aligned_same_size_identity_alias_edit_remains_committable(bool group)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = SameSizeAliasImage(group, 4);
        var source = fixture.Entry.ObjectSecurity;
        var peer = new ActiveDirectorySecurity(source._securityDescriptor, AllEntrySections);
        var before = source.CaptureInteropSnapshot();
        if (group) peer.SetGroup(new SecurityIdentifier(U2, 0));
        else peer.SetOwner(new SecurityIdentifier(U2, 0));
        var after = source.CaptureInteropSnapshot();
        Assert.Equal(80, after.Raw.Length);
        Assert.Equal(72u, BinaryPrimitives.ReadUInt32LittleEndian(after.Raw.AsSpan(12)));
        Assert.Equal(before.Generation + 1, after.Generation);
        Assert.Equal(before.Raw, after.Original);
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)),
            group ? AdForLinux.DirectoryServices.SecurityMasks.Group : AdForLinux.DirectoryServices.SecurityMasks.Owner, after.Raw);
    }

    private static byte[] SameSizeAliasImage(bool group, int gap)
    {
        var raw = LayoutRelocationCases.PrefixGap(Build(U1, Everyone, Acl(4)), gap, 0xEE);
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(2), 0x8014);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(12), (uint)(28 + gap));
        new byte[] { 4, 0, 8, 0, 0, 0, 0, 0 }.CopyTo(raw, 28 + gap);
        if (group)
        {
            var owner = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4));
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4), BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(8)));
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), owner);
        }
        return raw;
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Detached_copies_keep_existing_alias_alignment_semantics_without_entry_constraint(bool group, bool stateCopy)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = SameSizeAliasImage(group, 3);
        var source = fixture.Entry.ObjectSecurity;
        var before = StateBoundary.Take(source);
        var descriptor = stateCopy ? source._securityDescriptor.CopyDetachedState()
            : new AdForLinux.Security.AccessControl.CommonSecurityDescriptor(true, true, fixture.Raw, 0);
        var detached = new ActiveDirectorySecurity(descriptor, AllEntrySections);
        Assert.False(detached.HasRawReadContext);
        Assert.Null(detached.CaptureIdentityRead().Resolver);
        if (group) detached.SetGroup(new SecurityIdentifier(U2, 0));
        else detached.SetOwner(new SecurityIdentifier(U2, 0));
        var after = detached.CaptureInteropSnapshot();
        Assert.Equal(80, after.Raw.Length);
        Assert.Equal(0, after.Raw[71]);
        Assert.Equal(72u, BinaryPrimitives.ReadUInt32LittleEndian(after.Raw.AsSpan(12)));
        Assert.Equal(fixture.Raw.AsSpan(20, 3).ToArray(), after.Raw.AsSpan(20, 3).ToArray());
        AssertBoundRollback(before);
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Bound_storage_preflight_rolls_back_shared_acl_alias_edit()
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = SameSizeAliasImage(false, 3);
        var source = fixture.Entry.ObjectSecurity;
        var alias = IdenticalAlias(source._securityDescriptor);
        var before = StateBoundary.Take(source);
        var other = StateBoundary.Take(alias);
        Assert.Throws<InvalidOperationException>(() => alias.Descriptor.SystemAcl!.AddAudit(
            AuditFlags.Success, new SecurityIdentifier(U2, 0), 16, 0, 0));
        AssertBoundRollback(before);
        other.Check(AccessControlSections.None, false, false);
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Entry_assignment_installs_destination_storage_constraint_on_its_detached_copy()
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = SameSizeAliasImage(false, 3);
        var source = fixture.Entry.ObjectSecurity;
        var before = StateBoundary.Take(source);
        var supplied = new ActiveDirectorySecurity();
        supplied.SetOwner(new SecurityIdentifier(U2, 0));
        var suppliedBefore = StateBoundary.Take(supplied);
        Assert.Throws<InvalidOperationException>(() => fixture.Entry.ObjectSecurity = supplied);
        Assert.Same(source, fixture.Entry.ObjectSecurity);
        AssertBoundRollback(before);
        suppliedBefore.Check(AccessControlSections.None, false, false);
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }
}
