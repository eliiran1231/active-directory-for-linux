using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Security.Core;
using AdForLinux.Tests.Shared;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class AclMutationEngineTests
{
    public static IEnumerable<object[]> ContainedAclDestinations()
    {
        foreach (var topology in new[] { "owner", "ace-sid", "equal" })
        foreach (var sacl in new[] { false, true })
        foreach (var shrink in new[] { false, true })
        foreach (var payload in new[] { "clean", "reserved1", "reserved2", "acl-tail", "opaque" })
            yield return new object[] { topology, sacl, shrink, payload };
    }

    [Theory]
    [MemberData(nameof(ContainedAclDestinations))]
    public void Every_relocated_acl_checks_original_payload_including_aliases(string topology, bool sacl, bool shrink, string payload)
    {
        var nested = payload switch
        {
            "acl-tail" => AclWithTail(4, new byte[] { 0xA5, 0, 0, 0 }),
            "opaque" => Acl(4, new byte[] { 0x42, 0, 4, 0 }),
            _ => Acl(4)
        };
        if (payload == "reserved1") nested[1] = 0xA5;
        if (payload == "reserved2") nested[6] = 0xA5;
        var outer = topology == "equal" ? nested
            : topology == "ace-sid" ? Acl(4, Ace(sacl ? (byte)0 : (byte)2, sacl ? (byte)0 : (byte)64, 16, U1))
            : Acl(4);
        var raw = LayoutRelocationCases.PrefixGap(Build(U1, Everyone,
            sacl ? outer : null, sacl ? null : outer), 4, 0xEE);
        var outerOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(sacl ? 16 : 12));
        var aliasOffset = topology == "owner" ? 32 : topology == "ace-sid" ? outerOffset + 24 : outerOffset;
        nested.CopyTo(raw, aliasOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(2), 0x8014);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(sacl ? 12 : 16), (uint)aliasOffset);
        var original = SecurityDescriptor.Parse(raw, (SecurityMasks)15);
        var replacements = new Dictionary<SecurityMasks, byte[]?> { [SecurityMasks.Owner] = shrink ? Everyone : U2 };
        if (payload == "clean")
        {
            var edited = DescriptorRewriter.Rewrite(original, original.Control, replacements);
            Assert.False(edited.HasOverlappingComponents);
            Assert.Equal(SecurityMasks.Owner, edited.NetChangedSections(original));
            Assert.Equal(nested, ReplacementAcl(edited.GetBinaryForm(), sacl));
            foreach (var offset in Unreferenced(raw)) Assert.Equal(raw[offset], edited.GetBinaryForm()[offset]);
        }
        else Assert.Throws<InvalidOperationException>(() => DescriptorRewriter.Rewrite(original, original.Control, replacements));
        Assert.Equal(raw, original.GetBinaryForm());
    }

    private static byte[] ReplacementAcl(byte[] image, bool sacl)
    {
        var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(sacl ? 12 : 16));
        var length = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset + 2));
        return image.AsSpan(offset, length).ToArray();
    }
}
