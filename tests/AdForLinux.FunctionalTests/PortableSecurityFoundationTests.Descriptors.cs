#pragma warning disable CA1416 // Framework enum values only; descriptor implementation is portable.
using System.Security.AccessControl;
using Xunit;
using D = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Public_raw_descriptor_keeps_flags_and_optional_components_independent()
    {
        var acl = new D.RawAcl(4, 0);
        var descriptor = new D.RawSecurityDescriptor(ControlFlags.None, null, null, acl, acl);
        Assert.Equal(ControlFlags.SelfRelative, descriptor.ControlFlags);
        Assert.Same(acl, descriptor.SystemAcl);
        Assert.Same(acl, descriptor.DiscretionaryAcl);
        Assert.Equal(20, descriptor.BinaryLength);
        descriptor.SetFlags(ControlFlags.DiscretionaryAclPresent | ControlFlags.SystemAclPresent);
        Assert.Equal(36, descriptor.BinaryLength);
        var bytes = DescriptorBytes(descriptor);
        var reparsed = new D.RawSecurityDescriptor(bytes, 0);
        Assert.NotSame(reparsed.SystemAcl, reparsed.DiscretionaryAcl);
        Assert.Equal(bytes, DescriptorBytes(reparsed));
    }

    [Fact]
    public void Public_raw_resource_manager_byte_serializes_only_when_marked_valid()
    {
        var descriptor = new D.RawSecurityDescriptor(ControlFlags.None, null, null, null, null)
        { ResourceManagerControl = 0x5a };
        Assert.Equal(0, DescriptorBytes(descriptor)[1]);
        descriptor.SetFlags(ControlFlags.RMControlValid);
        Assert.Equal(0x5a, DescriptorBytes(descriptor)[1]);
        Assert.Equal(0x5a, new D.RawSecurityDescriptor(DescriptorBytes(descriptor), 0).ResourceManagerControl);
        descriptor.SetFlags(ControlFlags.None);
        Assert.Equal(0x5a, descriptor.ResourceManagerControl);
        Assert.Equal(0, new D.RawSecurityDescriptor(DescriptorBytes(descriptor), 0).ResourceManagerControl);
    }

    [Fact]
    public void Public_common_null_dacl_is_materialized_in_memory_but_clean_serialization_stays_absent()
    {
        var descriptor = new D.CommonSecurityDescriptor(true, true, ControlFlags.None, null, null, null, null);
        var rule = Assert.IsType<D.CommonAce>(descriptor.DiscretionaryAcl![0]);
        Assert.Equal("S-1-1-0", rule.SecurityIdentifier.Value);
        Assert.Equal(-1, rule.AccessMask);
        Assert.Equal(AceFlags.ContainerInherit | AceFlags.ObjectInherit, rule.AceFlags);
        Assert.True((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0);
        Assert.Equal(20, descriptor.BinaryLength);
        Assert.Equal(ControlFlags.SelfRelative, new D.RawSecurityDescriptor(DescriptorBytes(descriptor), 0).ControlFlags);
        descriptor.SetDiscretionaryAclProtection(true, true);
        Assert.NotNull(new D.RawSecurityDescriptor(DescriptorBytes(descriptor), 0).DiscretionaryAcl);
    }

    [Fact]
    public void Public_common_descriptor_clones_raw_acls_and_identity_assignment_is_independent()
    {
        var owner = new P.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var acl = new D.RawAcl(4, 1);
        acl.InsertAce(0, new D.CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 16, owner, false, null));
        var raw = new D.RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, owner, null, null, acl);
        var common = new D.CommonSecurityDescriptor(true, true, raw);
        acl.RemoveAce(0);
        raw.Owner = null;
        Assert.Single(common.DiscretionaryAcl!.Cast<D.GenericAce>());
        Assert.Same(owner, common.Owner);
        Assert.Empty(acl.Cast<D.GenericAce>());
    }

    [Fact]
    public void Public_descriptor_binary_offset_and_validation_are_managed_and_bounded()
    {
        var descriptor = new D.RawSecurityDescriptor(ControlFlags.None, new P.SecurityIdentifier("S-1-1-0"), null, null, null);
        var bytes = Enumerable.Repeat((byte)0xaa, descriptor.BinaryLength + 6).ToArray();
        descriptor.GetBinaryForm(bytes, 3);
        Assert.All(bytes.Take(3).Concat(bytes.TakeLast(3)), b => Assert.Equal(0xaa, b));
        Assert.Equal(DescriptorBytes(descriptor), DescriptorBytes(new D.RawSecurityDescriptor(bytes, 3)));
        Assert.Equal("binaryForm", Assert.Throws<ArgumentNullException>(() => descriptor.GetBinaryForm(null!, -1)).ParamName);
        Assert.Equal("offset", Assert.Throws<ArgumentOutOfRangeException>(() => descriptor.GetBinaryForm(bytes, -1)).ParamName);
        Assert.Equal("binaryForm", Assert.Throws<ArgumentOutOfRangeException>(() => new D.RawSecurityDescriptor(new byte[19], 0)).ParamName);
        var invalid = DescriptorBytes(descriptor);
        invalid[3] &= 0x7f;
        Assert.Equal("binaryForm", Assert.Throws<ArgumentException>(() => new D.RawSecurityDescriptor(invalid, 0)).ParamName);
    }

    [Fact]
    public void Public_common_acl_assignment_rejects_wrong_container_without_changing_descriptor()
    {
        var descriptor = new D.CommonSecurityDescriptor(true, true, ControlFlags.None, null, null, null,
            new D.DiscretionaryAcl(true, true, 0));
        var before = DescriptorBytes(descriptor);
        Assert.Throws<ArgumentException>(() => descriptor.DiscretionaryAcl = new D.DiscretionaryAcl(false, true, 0));
        Assert.Throws<ArgumentException>(() => descriptor.SystemAcl = new D.SystemAcl(true, false, 0));
        Assert.Equal(before, DescriptorBytes(descriptor));
    }

    private static byte[] DescriptorBytes(D.GenericSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
