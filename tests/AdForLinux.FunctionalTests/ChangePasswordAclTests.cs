using System.Buffers.Binary;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class ChangePasswordAclTests
{
    // Fixed object ACEs for the change-password right, granted to SELF and Everyone.
    private static byte[] SelfAllow() => Convert.FromHexString(
        "050028000001000001000000531A72AB2F1ED011981900AA0040529B01010000000000050A000000");
    private static byte[] WorldAllow() => Convert.FromHexString(
        "050028000001000001000000531A72AB2F1ED011981900AA0040529B010100000000000100000000");
    private static byte[] OwnerSid() => Convert.FromHexString("010100000000000512000000");
    private static byte[] GroupSid() => Convert.FromHexString("010100000000000520000000");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Adding_denies_preserves_components_and_relocates_only_offsets_after_dacl(bool ownerBeforeDacl)
    {
        var original = Descriptor(Array.Empty<byte[]>(), ownerBeforeDacl);
        var snapshot = original.ToArray();

        var changed = ChangePasswordAcl.SetDenied(original, true);

        Assert.Equal(snapshot, original);
        Assert.Equal(original.Length + 80, changed.Length);
        Assert.Equal(ReadOffset(original, 16), ReadOffset(changed, 16));
        Assert.Equal(ReadOffset(original, 4) + (ownerBeforeDacl ? 0 : 80), ReadOffset(changed, 4));
        Assert.Equal(ReadOffset(original, 8) + 80, ReadOffset(changed, 8));
        Assert.Equal(ReadOffset(original, 12) + 80, ReadOffset(changed, 12));
        Assert.Equal(original[..4], changed[..4]);
        AssertComponents(changed);
        Assert.Collection(ReadAces(changed),
            ace => Assert.Equal(WithType(SelfAllow(), 6), ace),
            ace => Assert.Equal(WithType(WorldAllow(), 6), ace));
        Assert.True(ChangePasswordAcl.IsDenied(changed));
        Assert.False(ChangePasswordAcl.IsDenied(original));
    }

    [Fact]
    public void Enabling_password_changes_removes_duplicates_and_preserves_unrelated_ace_order()
    {
        var unrelatedDeny = Convert.FromHexString("010014000100000001010000000000050B000000");
        var unrelatedAllow = Convert.FromHexString("000014000100000001010000000000050B000000");
        var inherited = SelfAllow();
        inherited[1] = 0x10;
        var original = Descriptor(new[]
        {
            unrelatedDeny, WithType(SelfAllow(), 6), WithType(WorldAllow(), 6),
            SelfAllow(), WorldAllow(), unrelatedAllow, inherited,
        });
        var snapshot = original.ToArray();

        var changed = ChangePasswordAcl.SetDenied(original, false);

        Assert.Equal(snapshot, original);
        Assert.Equal(original.Length - 80, changed.Length);
        Assert.Collection(ReadAces(changed),
            ace => Assert.Equal(unrelatedDeny, ace),
            ace => Assert.Equal(unrelatedAllow, ace),
            ace => Assert.Equal(SelfAllow(), ace),
            ace => Assert.Equal(WorldAllow(), ace),
            ace => Assert.Equal(inherited, ace));
        foreach (var field in new[] { 4, 8, 12 })
        {
            Assert.Equal(ReadOffset(original, field) - 80, ReadOffset(changed, field));
        }
        AssertComponents(changed);
        Assert.False(ChangePasswordAcl.IsDenied(changed));
        Assert.Equal(changed, ChangePasswordAcl.SetDenied(changed, false));
    }

    [Fact]
    public void Denies_precede_existing_allows_and_repeated_toggles_do_not_grow_the_acl()
    {
        var unrelated = Convert.FromHexString("000014000100000001010000000000050B000000");
        var original = Descriptor(new[] { unrelated, SelfAllow(), WorldAllow() });

        var denied = ChangePasswordAcl.SetDenied(original, true);

        Assert.Collection(ReadAces(denied),
            ace => Assert.Equal(WithType(SelfAllow(), 6), ace),
            ace => Assert.Equal(WithType(WorldAllow(), 6), ace),
            ace => Assert.Equal(unrelated, ace));
        Assert.Equal(denied, ChangePasswordAcl.SetDenied(denied, true));
        Assert.Equal(original, ChangePasswordAcl.SetDenied(denied, false));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_deny_for_either_self_or_everyone_is_sufficient(bool everyone)
    {
        var ace = WithType(everyone ? WorldAllow() : SelfAllow(), 6);
        Assert.True(ChangePasswordAcl.IsDenied(Descriptor(new[] { ace })));
    }

    [Theory]
    [InlineData("inherited")]
    [InlineData("other-right")]
    [InlineData("other-trustee")]
    [InlineData("other-access-mask")]
    public void Similar_but_unrelated_object_aces_are_not_treated_as_explicit_password_denies(string difference)
    {
        var ace = WithType(SelfAllow(), 6);
        switch (difference)
        {
            case "inherited": ace[1] = 0x10; break;
            case "other-right": ace[12] ^= 1; break;
            case "other-trustee": ace[^4] = 11; break;
            case "other-access-mask": Write32(ace, 4, 0x10); break;
        }
        var descriptor = Descriptor(new[] { ace });

        Assert.False(ChangePasswordAcl.IsDenied(descriptor));
        var changed = ChangePasswordAcl.SetDenied(descriptor, true);
        Assert.Collection(ReadAces(changed),
            actual => Assert.Equal(WithType(SelfAllow(), 6), actual),
            actual => Assert.Equal(WithType(WorldAllow(), 6), actual),
            actual => Assert.Equal(ace, actual));
    }

    [Theory]
    [InlineData("short-header")]
    [InlineData("absent-dacl")]
    [InlineData("truncated-acl-header")]
    [InlineData("short-acl-size")]
    [InlineData("oversized-acl")]
    [InlineData("missing-ace")]
    [InlineData("short-ace")]
    [InlineData("oversized-ace")]
    public void Malformed_descriptors_fail_without_mutating_the_input(string defect)
    {
        var descriptor = Descriptor(new[] { SelfAllow() });
        const int dacl = 20;
        switch (defect)
        {
            case "short-header": descriptor = descriptor[..19]; break;
            case "absent-dacl": Write32(descriptor, 16, 0); break;
            case "truncated-acl-header": Write32(descriptor, 16, descriptor.Length - 4); break;
            case "short-acl-size": Write16(descriptor, dacl + 2, 7); break;
            case "oversized-acl": Write16(descriptor, dacl + 2, descriptor.Length); break;
            case "missing-ace": Write16(descriptor, dacl + 4, 2); break;
            case "short-ace": Write16(descriptor, dacl + 10, 3); break;
            case "oversized-ace": Write16(descriptor, dacl + 10, 44); break;
        }
        var snapshot = descriptor.ToArray();

        Assert.Throws<InvalidOperationException>(() => ChangePasswordAcl.IsDenied(descriptor));
        Assert.Throws<InvalidOperationException>(() => ChangePasswordAcl.SetDenied(descriptor, true));
        Assert.Throws<InvalidOperationException>(() => ChangePasswordAcl.SetDenied(descriptor, false));
        Assert.Equal(snapshot, descriptor);
    }

    private static byte[] Descriptor(byte[][] aces, bool ownerBeforeDacl = false)
    {
        var aclSize = 8 + aces.Sum(ace => ace.Length);
        var dacl = 20 + (ownerBeforeDacl ? 12 : 0);
        var descriptor = new byte[20 + 12 + aclSize + 12 + 8];
        descriptor[0] = 1;
        Write16(descriptor, 2, 0x8014); // Self-relative; DACL and SACL present.
        var owner = ownerBeforeDacl ? 20 : dacl + aclSize;
        var group = ownerBeforeDacl ? dacl + aclSize : owner + 12;
        Write32(descriptor, 4, owner);
        Write32(descriptor, 8, group);
        Write32(descriptor, 12, group + 12);
        Write32(descriptor, 16, dacl);
        OwnerSid().CopyTo(descriptor, owner);
        GroupSid().CopyTo(descriptor, group);
        descriptor[group + 12] = 2; // Empty SACL.
        Write16(descriptor, group + 14, 8);
        descriptor[dacl] = 4; // ACL_REVISION_DS for object ACEs.
        Write16(descriptor, dacl + 2, aclSize);
        Write16(descriptor, dacl + 4, aces.Length);
        var position = dacl + 8;
        foreach (var ace in aces)
        {
            ace.CopyTo(descriptor, position);
            position += ace.Length;
        }
        return descriptor;
    }

    private static void AssertComponents(byte[] descriptor)
    {
        Assert.Equal(OwnerSid(), descriptor.AsSpan(ReadOffset(descriptor, 4), 12).ToArray());
        Assert.Equal(GroupSid(), descriptor.AsSpan(ReadOffset(descriptor, 8), 12).ToArray());
        Assert.Equal(new byte[] { 2, 0, 8, 0, 0, 0, 0, 0 },
            descriptor.AsSpan(ReadOffset(descriptor, 12), 8).ToArray());
    }

    private static IEnumerable<byte[]> ReadAces(byte[] descriptor)
    {
        var offset = ReadOffset(descriptor, 16);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(offset + 4));
        var position = offset + 8;
        for (var i = 0; i < count; i++)
        {
            var size = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(position + 2));
            yield return descriptor.AsSpan(position, size).ToArray();
            position += size;
        }
        Assert.Equal(offset + BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(offset + 2)), position);
    }

    private static byte[] WithType(byte[] ace, byte type)
    {
        ace[0] = type;
        return ace;
    }

    private static int ReadOffset(byte[] bytes, int offset) =>
        checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)));

    private static void Write32(byte[] bytes, int offset, int value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), checked((uint)value));

    private static void Write16(byte[] bytes, int offset, int value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), checked((ushort)value));
}
