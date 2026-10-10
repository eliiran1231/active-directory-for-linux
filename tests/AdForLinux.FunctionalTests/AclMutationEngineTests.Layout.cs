using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using Xunit;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class AclMutationEngineTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(0xA5)]
    public void Fixed_layout_changes_preserve_every_gap_byte_and_offset(int fill)
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 0x10, U1)), sacl: Acl(4), gapBefore: 3, tail: new byte[] { (byte)fill, 0x39 });
        var gaps = Unreferenced(raw);
        foreach (var index in gaps) raw[index] = (byte)fill;
        var original = Engine(raw);
        var edited = original.SetOwner(Trustee(U2)).Engine.ModifyProjected(SecurityMasks.Dacl,
            AclModification.Set, CoreAce.Read(Ace(0, 0, 0x20, U1))).Engine.SetProtectionProjected(SecurityMasks.Dacl, true, true).Engine;
        var result = edited.Descriptor.GetBinaryForm();
        Assert.Equal(raw.Length, result.Length);
        Assert.Equal(raw.AsSpan(4, 16).ToArray(), result.AsSpan(4, 16).ToArray());
        foreach (var index in gaps) Assert.Equal(raw[index], result[index]);
        Assert.Equal(0x20u, Assert.Single(edited.GetObservableAcl(SecurityMasks.Dacl)!.Aces).AccessMask);
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Dacl, edited.WriteIntent);
        Assert.Equal(raw, original.Descriptor.GetBinaryForm());
        Assert.Equal(raw, edited.OriginalDescriptor.GetBinaryForm());
        Assert.NotEqual(result.Length, edited.GetObservableDescriptor().GetBinaryForm().Length);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Terminal_acl_resize_keeps_original_unknown_positions_and_other_sections(bool grow)
    {
        var raw = Build(Admins, Admins, Acl(4, Ace(0, 0, 0x10, U1)), sacl: Acl(4), gapBefore: 4);
        var engine = Engine(raw);
        var result = engine.Modify(SecurityMasks.Dacl, grow ? AclModification.Add : AclModification.RemoveSpecific,
            CoreAce.Read(Ace(0, 0, 0x10, grow ? U2 : U1))).Engine;
        var actual = result.Descriptor.GetBinaryForm();
        var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16));
        Assert.Equal(raw.AsSpan(0, offset).ToArray(), actual.AsSpan(0, offset).ToArray());
        Assert.Equal(grow ? raw.Length + 36 : raw.Length - 36, actual.Length);
        foreach (var index in Unreferenced(raw)) Assert.Equal(raw[index], actual[index]);
        Assert.Equal(raw, result.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Contained_sid_aliases_unshare_without_relocating_orphan_bytes()
    {
        var raw = Build(U2, U2, Acl(4, Ace(0, 0, 0x10, U1)), sacl: Acl(4), gapBefore: 4);
        var dacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4), (uint)(dacl + 16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), (uint)(dacl + 16));
        var gaps = Unreferenced(raw);
        var original = Engine(raw);
        Assert.True(original.Descriptor.HasOverlappingComponents);
        var changed = original.Modify(SecurityMasks.Dacl, AclModification.RemoveSpecific, Rule(0x10)).Engine;
        Assert.False(changed.Descriptor.HasOverlappingComponents);
        Assert.Equal(Trustee(U1), changed.Descriptor.Owner);
        Assert.Equal(Trustee(U1), changed.Descriptor.Group);
        Assert.Empty(changed.Descriptor.Dacl!.Aces);
        var result = changed.Descriptor.GetBinaryForm();
        foreach (var index in gaps) Assert.Equal(raw[index], result[index]);
        Assert.Equal(raw, original.Descriptor.GetBinaryForm());
        Assert.Equal(raw, changed.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Dacl, changed.WriteIntent);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Trailer_is_not_consumed_or_reclassified_for_resize_or_unsharing(bool zero)
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 0x10, U1)), tail: new byte[] { (byte)(zero ? 0 : 0xA5), 0, 0, 0 });
        var engine = Engine(raw).SetOwner(Trustee(U2)).Engine;
        var before = engine.Descriptor.GetBinaryForm();
        Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.Add, CoreAce.Read(Ace(0, 0, 0x10, U2))));
        Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.RemoveSpecific, Rule(0x10)));
        Assert.Equal(before, engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Owner, engine.WriteIntent);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4)));
        var shared = Engine(raw);
        var error = Assert.Throws<InvalidOperationException>(() => shared.SetOwner(Trustee(U2)));
        Assert.Contains("trailer", error.Message);
        Assert.Equal(raw, shared.Descriptor.GetBinaryForm());
    }

    [Fact]
    public void Gapped_terminal_acl_with_internal_opaque_tail_refuses_resize()
    {
        var raw = Build(U1, U1, AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(0, 0, 0x10, U1)), gapBefore: 4);
        var engine = Engine(raw);
        var error = Assert.Throws<InvalidOperationException>(() => engine.Modify(SecurityMasks.Dacl, AclModification.Add, CoreAce.Read(Ace(0, 0, 0x10, U2))));
        Assert.Contains("ACL trailing", error.Message);
        Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, engine.WriteIntent);
    }

    [Fact]
    public void Crossing_sid_spans_with_gaps_refuse_without_creating_orphan_storage()
    {
        var raw = new byte[52];
        raw[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(2), 0x8004);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4), 20);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), 28);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(16), 44);
        Sid.Parse("S-1-5-257").ToArray().CopyTo(raw, 20);
        Sid.Parse("S-1-5-7").ToArray().CopyTo(raw, 28);
        raw.AsSpan(40, 4).Fill(0xA5);
        Acl(4).CopyTo(raw, 44);
        var engine = Engine(raw);
        Assert.True(engine.Descriptor.HasOverlappingComponents);
        var failure = Assert.Throws<InvalidOperationException>(() => engine.SetOwner(Trustee(U2)));
        Assert.Contains("Crossing", failure.Message);
        Assert.Equal(raw, engine.Descriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.None, engine.WriteIntent);
    }

    [Fact]
    public void New_alias_storage_is_aligned_without_consuming_existing_unaligned_gaps()
    {
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 0x10, U1)), gapBefore: 3);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4)));
        Assert.NotEqual(0, raw.Length % 4);
        var engine = Engine(raw);
        var changed = engine.SetGroup(Trustee(U2)).Engine;
        var result = changed.Descriptor.GetBinaryForm();
        var group = (int)BinaryPrimitives.ReadUInt32LittleEndian(result.AsSpan(8));
        Assert.Equal(0, group % 4);
        Assert.True(group >= raw.Length);
        foreach (var index in Unreferenced(raw)) Assert.Equal(raw[index], result[index]);
        Assert.All(result.AsSpan(raw.Length, group - raw.Length).ToArray(), value => Assert.Equal((byte)0, value));
        Assert.Equal(Trustee(U1), changed.Descriptor.Owner);
        Assert.Equal(Trustee(U2), changed.Descriptor.Group);
        Assert.False(changed.Descriptor.HasOverlappingComponents);
    }

    private static int[] Unreferenced(byte[] image)
    {
        var used = new bool[image.Length];
        Array.Fill(used, true, 0, 20);
        foreach (var field in new[] { 4, 8, 12, 16 })
        {
            var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(field));
            if (offset == 0) continue;
            var length = field < 12 ? 8 + image[offset + 1] * 4 : BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset + 2));
            Array.Fill(used, true, offset, length);
        }
        return Enumerable.Range(20, image.Length - 20).Where(i => !used[i]).ToArray();
    }
}
