#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using C = AdForLinux.DirectoryServices.Security.Core;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_wire_mask_omits_reverted_identity_section_with_other_changes(bool revertOwner)
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        security.SetGroup(new SecurityIdentifier(U2, 0));
        if (revertOwner) security.SetOwner(new SecurityIdentifier(U1, 0));
        else security.SetGroup(new SecurityIdentifier(U1, 0));
        fixture.Entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal(revertOwner ? System.DirectoryServices.Protocols.SecurityMasks.Group : System.DirectoryServices.Protocols.SecurityMasks.Owner,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_wire_mask_omits_reverted_acl_protection_without_normalizing_raw_storage(bool revertDacl)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = Build(U1, U1,
            AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(0, 0, 16, U1)),
            AclWithTail(4, new byte[] { 9, 10, 11, 12 }, Ace(2, 0x40, 16, U1)));
        var security = fixture.Entry.ObjectSecurity;
        security.SetAccessRuleProtection(true, true); security.SetAuditRuleProtection(true, true);
        if (revertDacl) security.SetAccessRuleProtection(false, true);
        else security.SetAuditRuleProtection(false, true);
        var expected = security._securityDescriptor.MutationState.Descriptor.GetBinaryForm();
        fixture.Entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal(revertDacl ? System.DirectoryServices.Protocols.SecurityMasks.Sacl : System.DirectoryServices.Protocols.SecurityMasks.Dacl,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
        Assert.Equal(expected, Assert.IsType<byte[]>(request.Modifications[0][0]));
    }

    [Theory]
    [InlineData(1, 1)] [InlineData(2, 2)] [InlineData(8, 4)] [InlineData(32, 8)]
    [InlineData(0x100, 4)] [InlineData(0x200, 8)] [InlineData(0x400, 4)] [InlineData(0x800, 8)]
    [InlineData(0x1000, 4)] [InlineData(0x2000, 8)]
    public void Raw_net_section_comparison_retains_associated_control_bits(int bit, int section)
    {
        var original = Build(U1, U1, Acl(4), Acl(4)); var changed = (byte[])original.Clone();
        var flags = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(changed.AsSpan(2));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(changed.AsSpan(2), (ushort)(flags | bit));
        Assert.Equal((EntryMasks)section, C.SecurityDescriptor.Parse(changed, AllEntrySections)
            .NetChangedSections(C.SecurityDescriptor.Parse(original, AllEntrySections)));
    }

    [Theory]
    [InlineData("header")] [InlineData("unknown-control")] [InlineData("gap")]
    public void Raw_net_section_comparison_refuses_unattributable_unknown_changes(string change)
    {
        var original = Build(U1, U1, Acl(4), gapBefore: 4); var changed = (byte[])original.Clone();
        if (change == "header") changed[1] ^= 1;
        else if (change == "gap") changed[20] ^= 1;
        else changed[2] ^= 0x40;
        Assert.Throws<InvalidOperationException>(() => C.SecurityDescriptor.Parse(changed, AllEntrySections)
            .NetChangedSections(C.SecurityDescriptor.Parse(original, AllEntrySections)));
        Assert.Equal(EntryMasks.None, C.SecurityDescriptor.Parse(original, AllEntrySections)
            .NetChangedSections(C.SecurityDescriptor.Parse(original, AllEntrySections)));
    }
}
