using P = AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-21-1-2-3-4294967295")]
    [InlineData("S-1-18838586676582-7")]
    public void Numeric_sid_has_defensive_binary_value_semantics(string text)
    {
        var sid = new P.SecurityIdentifier(text);
        var source = new byte[sid.BinaryLength + 8];
        Array.Fill(source, (byte)0xa5);
        sid.GetBinaryForm(source, 4);
        var copy = new P.SecurityIdentifier(source, 4);
        Array.Clear(source);
        Assert.Equal(text, copy.Value);
        Assert.Equal(sid, copy);
        Assert.Equal(sid.GetHashCode(), copy.GetHashCode());
        Assert.Equal(0, sid.CompareTo(copy));
        Assert.Same(sid, sid.Translate(typeof(P.SecurityIdentifier)));
    }

    [Fact]
    public void Numeric_sid_binary_roundtrip_is_deterministic_for_all_lengths()
    {
        var random = new Random(226_1007);
        for (var count = 0; count <= 15; count++)
        for (var sample = 0; sample < 32; sample++)
        {
            var bytes = new byte[8 + 4 * count];
            random.NextBytes(bytes); bytes[0] = 1; bytes[1] = (byte)count;
            var sid = new P.SecurityIdentifier(bytes, 0);
            // Binary SID construction accepts zero sub-authorities; Windows SDDL text does not.
            var parsed = count == 0 ? new P.SecurityIdentifier(bytes, 0) : new P.SecurityIdentifier(sid.Value);
            var roundtrip = new byte[bytes.Length]; parsed.GetBinaryForm(roundtrip, 0);
            Assert.Equal(bytes, roundtrip);
            Assert.Equal(sid, parsed);
        }
    }

    [Fact]
    public void Names_remain_unresolved_case_insensitive_values()
    {
        var account = new P.NTAccount("EXAMPLE", "SomeUser");
        Assert.Equal("EXAMPLE\\SomeUser", account.Value);
        Assert.Equal(account, new P.NTAccount("example\\someuser"));
        Assert.Equal(account.GetHashCode(), new P.NTAccount("example\\someuser").GetHashCode());
        Assert.Same(account, account.Translate(typeof(P.NTAccount)));
        Assert.False(account.IsValidTargetType(typeof(string)));
    }

    [Fact]
    public void Foundation_translation_does_not_infer_resolver_authority()
    {
        P.IdentityReference sid = new P.SecurityIdentifier("S-1-1-0");
        P.IdentityReference account = new P.NTAccount("unresolved");
        Assert.Throws<NotSupportedException>(() => sid.Translate(typeof(P.NTAccount)));
        Assert.Throws<NotSupportedException>(() => account.Translate(typeof(P.SecurityIdentifier)));
        Assert.Equal("targetType", Assert.Throws<ArgumentNullException>(() => sid.Translate(null!)).ParamName);
        Assert.Equal("targetType", Assert.Throws<ArgumentException>(() => account.Translate(typeof(string))).ParamName);
        Assert.False(sid.IsValidTargetType(null!));
    }
}
