using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using AdForLinux.Tests.Shared;
using Xunit;
using CoreAce = AdForLinux.DirectoryServices.Security.Core.Ace;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class AclMutationEngineTests
{
    [Theory]
    [InlineData("gap")] [InlineData("trailer")] [InlineData("acl-tail")]
    [InlineData("ace-tail")] [InlineData("callback")] [InlineData("reserved")]
    [InlineData("revision")] [InlineData("reserved-ace-flag")]
    public void Interior_resize_refuses_to_shift_unexplained_storage_with_prior_intent(string obstacle)
    {
        var ace = Ace(obstacle == "callback" ? (byte)9 : (byte)0,
            obstacle == "reserved-ace-flag" ? (byte)0x20 : (byte)0, 16, U1,
            obstacle == "ace-tail" ? new byte[] { 7, 8, 9, 10 } : null);
        var acl = AclWithTail(obstacle == "revision" ? (byte)3 : (byte)4,
            obstacle == "acl-tail" ? new byte[] { 1, 2, 3, 4 } : [], ace);
        if (obstacle == "reserved") acl[1] = 0xA5;
        var raw = LayoutRelocationCases.PrefixGap(Build(U1, U1, acl,
            gapBefore: obstacle == "gap" ? 4 : 0,
            tail: obstacle == "trailer" ? new byte[] { 0, 0, 0, 0 } : null), 4, 0xA5);
        var engine = Engine(raw).SetGroup(Trustee(U2)).Engine;
        var before = engine.Descriptor.GetBinaryForm();
        Assert.Throws<InvalidOperationException>(() => engine.SetOwner(Trustee(Everyone)));
        Assert.Equal(before, engine.Descriptor.GetBinaryForm());
        Assert.Equal(raw, engine.OriginalDescriptor.GetBinaryForm());
        Assert.Equal(SecurityMasks.Group, engine.WriteIntent);
        var sameSize = engine.SetOwner(Trustee(U2)).Engine;
        foreach (var offset in Unreferenced(raw)) Assert.Equal(raw[offset], sameSize.Descriptor.GetBinaryForm()[offset]);
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Group, sameSize.WriteIntent);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Moving_suffix_copies_contained_sid_aliases_from_immutable_source(bool grow)
    {
        var audit = grow ? Acl(4, Ace(2, 64, 16, U1)) : Acl(4, Ace(2, 64, 16, U1), Ace(2, 64, 16, U2));
        var raw = LayoutRelocationCases.PrefixGap(Build(U2, U2, Acl(4, Ace(0, 0, 16, U1)), audit), 4, 0xA5);
        var dacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(4), (uint)(dacl + 16));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(8), (uint)(dacl + 16));
        var original = Engine(raw);
        var edited = original.Modify(SecurityMasks.Sacl, grow ? AclModification.Add : AclModification.RemoveSpecific,
            CoreAce.Read(Ace(2, 64, 16, U2))).Engine;
        var actual = edited.Descriptor.GetBinaryForm();
        var movedEnd = raw.Length + (grow ? 36 : -36);
        Assert.Equal(movedEnd + U1.Length * 2, actual.Length);
        Assert.Equal((uint)movedEnd, BinaryPrimitives.ReadUInt32LittleEndian(actual.AsSpan(4)));
        Assert.Equal((uint)(movedEnd + U1.Length), BinaryPrimitives.ReadUInt32LittleEndian(actual.AsSpan(8)));
        Assert.Equal(Trustee(U1), edited.Descriptor.Owner);
        Assert.Equal(Trustee(U1), edited.Descriptor.Group);
        Assert.False(edited.Descriptor.HasOverlappingComponents);
        Assert.Equal(original.Descriptor.Dacl!.Aces.Single().RawBytes.ToArray(), edited.Descriptor.Dacl!.Aces.Single().RawBytes.ToArray());
        foreach (var offset in Unreferenced(raw)) Assert.Equal(raw[offset], actual[offset]);
        Assert.Equal(SecurityMasks.Sacl, edited.Descriptor.NetChangedSections(original.Descriptor));
        Assert.Equal(SecurityMasks.Sacl, edited.WriteIntent);
        Assert.Equal(raw, original.Descriptor.GetBinaryForm());
        Assert.Equal(raw, edited.OriginalDescriptor.GetBinaryForm());
    }

    [Fact]
    public void Multiple_suffix_resizes_use_final_component_lengths_without_orphaning_bytes()
    {
        var raw = LayoutRelocationCases.PrefixGap(Build(Everyone, U1, Acl(4), Acl(4)), 4, 0xA5);
        var original = SecurityDescriptor.Parse(raw, (SecurityMasks)15);
        var edited = DescriptorRewriter.Rewrite(original, original.Control, new Dictionary<SecurityMasks, byte[]?>
        { [SecurityMasks.Owner] = U1, [SecurityMasks.Group] = Everyone });
        var expected = LayoutRelocationCases.PrefixGap(Build(U1, Everyone, Acl(4), Acl(4)), 4, 0xA5);
        Assert.Equal(expected, edited.GetBinaryForm());
        Assert.Equal(raw.Length, expected.Length);
        Assert.Equal(SecurityMasks.Owner | SecurityMasks.Group, edited.NetChangedSections(original));
        Assert.Equal(raw, original.GetBinaryForm());
    }
}
