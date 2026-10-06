using AdForLinux.DirectoryServices.Security.Core;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>Offline tests for the internal portable <see cref="Sid"/> value.</summary>
public class CoreSidTests
{
    [Theory]
    [InlineData("S-1-1-0", "010100000000000100000000")]
    [InlineData("S-1-5-32-544", "01020000000000052000000020020000")]
    [InlineData("S-1-5-21-1-2-3-4294967295", "010500000000000515000000010000000200000003000000FFFFFFFF")]
    public void Text_and_binary_forms_round_trip(string text, string hex)
    {
        var sid = Sid.Parse(text);

        Assert.Equal(hex, Convert.ToHexString(sid.AsSpan()));
        Assert.Equal(text, sid.ToString());
        Assert.True(Sid.TryRead(Convert.FromHexString(hex), out var read, out var consumed));
        Assert.Equal(sid, read);
        Assert.Equal(hex.Length / 2, consumed);
    }

    [Fact]
    public void Hex_authority_input_is_accepted_and_formatted_in_decimal()
    {
        var sid = Sid.Parse("S-1-0x112233445566-7");

        Assert.Equal(0x112233445566UL, sid.IdentifierAuthority);
        Assert.Equal("S-1-18838586676582-7", sid.ToString());
    }

    [Fact]
    public void Fifteen_sub_authorities_are_the_maximum()
    {
        var fifteen = "S-1-5" + string.Concat(Enumerable.Range(1, 15).Select(i => "-" + i));

        var sid = Sid.Parse(fifteen);

        Assert.Equal(Sid.MaxBinaryLength, sid.BinaryLength);
        Assert.Throws<ArgumentException>(() => Sid.Parse(fifteen + "-16"));
    }

    [Fact]
    public void Read_consumes_only_the_sid_and_ignores_following_bytes()
    {
        var buffer = Convert.FromHexString("010100000000000100000000AABBCCDD");

        Assert.True(Sid.TryRead(buffer, out var sid, out var consumed));

        Assert.Equal(12, consumed);
        Assert.Equal("S-1-1-0", sid!.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("01")]
    [InlineData("0201000000000001")]
    [InlineData("0110000000000001")]
    [InlineData("01020000000000052000000020")]
    public void Invalid_binary_sids_are_not_read(string hex)
    {
        Assert.False(Sid.TryRead(Convert.FromHexString(hex), out var sid, out var consumed));
        Assert.Null(sid);
        Assert.Equal(0, consumed);
    }

    [Theory]
    [InlineData("BA")]
    [InlineData("S-1")]
    [InlineData("S-2-5-32")]
    [InlineData("S-1-5- 32")]
    [InlineData("S-1-5-+32")]
    [InlineData("S-1-5--32")]
    [InlineData("S-1-5-4294967296")]
    [InlineData("S-1-281474976710656")]
    [InlineData("S-1-0x1000000000000")]
    public void Invalid_text_is_rejected(string text)
    {
        var error = Assert.Throws<ArgumentException>(() => Sid.Parse(text));

        Assert.Equal("value", error.ParamName);
    }

    [Fact]
    public void Equality_is_by_bytes_and_copies_are_independent()
    {
        var first = Sid.Parse("S-1-5-32-544");
        var second = Sid.Parse("S-1-0x5-32-544");
        var copy = first.ToArray();
        copy[0] = 9;

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.NotEqual(first, Sid.Parse("S-1-5-32-545"));
        Assert.Equal(1, first.AsSpan()[0]);
    }
}
