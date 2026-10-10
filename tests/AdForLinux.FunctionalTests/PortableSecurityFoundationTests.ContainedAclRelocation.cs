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
}
