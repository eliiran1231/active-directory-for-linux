using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class SidCodecTests
{
    [Fact]
    public void Sid_uses_big_endian_authority_and_unsigned_little_endian_subauthorities()
    {
        byte[] binary =
        {
            1, 2, 1, 2, 3, 4, 5, 6,
            4, 3, 2, 1,
            255, 255, 255, 255,
        };

        Assert.Equal(binary, SidCodec.Parse("s-1-0x010203040506-16909060-4294967295"));
        Assert.Equal("S-1-1108152157446-16909060-4294967295", SidCodec.Format(binary));
        Assert.Equal(uint.MaxValue, SidCodec.GetRid(binary));
    }

    [Fact]
    public void Maximum_authority_and_fifteen_subauthorities_are_preserved()
    {
        var text = "S-1-281474976710655-" + string.Join("-", Enumerable.Repeat("4294967295", 15));
        var expected = new byte[] { 1, 15 }.Concat(Enumerable.Repeat((byte)255, 66)).ToArray();

        Assert.Equal(expected, SidCodec.Parse(text));
        Assert.Equal(text, SidCodec.Format(expected));
        Assert.Throws<ArgumentException>(() => SidCodec.Parse(text + "-1"));
    }

    [Theory]
    [InlineData(0u, "00000000")]
    [InlineData(513u, "01020000")]
    [InlineData(2147483648u, "00000080")]
    [InlineData(uint.MaxValue, "FFFFFFFF")]
    public void Replacing_rid_preserves_domain_and_original_buffer(uint rid, string expectedRidHex)
    {
        var original = Convert.FromHexString("0105000000000005150000006F000000DE0000004D01000053040000");
        var snapshot = original.ToArray();

        var replaced = SidCodec.ReplaceRid(original, rid);

        Assert.NotSame(original, replaced);
        Assert.Equal(snapshot, original);
        Assert.Equal(snapshot[..^4], replaced[..^4]);
        Assert.Equal(Convert.FromHexString(expectedRidHex), replaced[^4..]);
        Assert.Equal(rid, SidCodec.GetRid(replaced));
        Assert.Equal(1107u, SidCodec.GetRid(original));
    }

    [Theory]
    [InlineData("")]
    [InlineData("01000000000000")]
    [InlineData("020100000000000501000000")]
    [InlineData("010200000000000501000000")]
    [InlineData("011000000000000501000000")]
    public void Malformed_binary_sids_are_rejected_before_reading_or_replacing_rid(string hex)
    {
        var bytes = Convert.FromHexString(hex);
        var snapshot = bytes.ToArray();

        Assert.Equal("value", Assert.Throws<ArgumentException>(() => SidCodec.Format(bytes)).ParamName);
        Assert.Equal("value", Assert.Throws<ArgumentException>(() => SidCodec.GetRid(bytes)).ParamName);
        Assert.Equal("value", Assert.Throws<ArgumentException>(() => SidCodec.ReplaceRid(bytes, 513)).ParamName);
        Assert.Equal(snapshot, bytes);
    }

    [Fact]
    public void Authority_only_sid_has_no_rid()
    {
        var bytes = new byte[] { 1, 0, 0, 0, 0, 0, 0, 5 };

        Assert.Equal(bytes, SidCodec.Parse("S-1-5"));
        Assert.Equal("S-1-5", SidCodec.Format(bytes));
        Assert.Throws<ArgumentException>(() => SidCodec.GetRid(bytes));
        Assert.Throws<ArgumentException>(() => SidCodec.ReplaceRid(bytes, 513));
    }

    [Theory]
    [InlineData("S-1-0x1000000000000-1")]
    [InlineData("S-1-0x-1")]
    [InlineData("S-1-5--1")]
    [InlineData("S-1-5-+1")]
    [InlineData("S-1-5-1 ")]
    [InlineData("S-1-5-")]
    public void Invalid_numeric_components_are_not_silently_normalized(string text)
    {
        Assert.Equal("value", Assert.Throws<ArgumentException>(() => SidCodec.Parse(text)).ParamName);
    }
}
