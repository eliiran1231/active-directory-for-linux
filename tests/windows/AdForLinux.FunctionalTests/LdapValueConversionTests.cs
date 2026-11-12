using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class LdapValueConversionTests
{
    [Theory]
    [InlineData("2.5.5.8", "1", "Boolean")]
    [InlineData("2.5.5.9", "2", "Int32")]
    [InlineData("2.5.5.9", "10", "Int32")]
    [InlineData("2.5.5.16", "65", "Int64")]
    [InlineData("2.5.5.11", "23", "DateTime")]
    [InlineData("2.5.5.11", "24", "DateTime")]
    [InlineData("2.5.5.10", "4", "Binary")]
    [InlineData("2.5.5.10", "127", "Binary")]
    [InlineData("2.5.5.15", "66", "Binary")]
    [InlineData("2.5.5.17", "4", "Binary")]
    [InlineData("2.5.5.12", "64", "String")]
    public void Schema_syntax_selects_the_CLR_representation(
        string attributeSyntax,
        string omSyntax,
        string expected)
    {
        Assert.Equal(expected, LdapAttributeSchema.KindFromSyntax(attributeSyntax, omSyntax).ToString());
    }

    [Fact]
    public void Conversion_uses_exact_invariant_CLR_types()
    {
        Assert.IsType<bool>(SearchEntryReader.ConvertValue("TRUE", LdapValueKind.Boolean));
        Assert.IsType<int>(SearchEntryReader.ConvertValue("512", LdapValueKind.Int32));
        Assert.IsType<long>(SearchEntryReader.ConvertValue("9223372036854775807", LdapValueKind.Int64));

        var timestamp = Assert.IsType<DateTime>(
            SearchEntryReader.ConvertValue("20310203040506.0Z", LdapValueKind.DateTime));
        Assert.Equal(new DateTime(2031, 2, 3, 4, 5, 6, DateTimeKind.Unspecified), timestamp);
    }

    [Fact]
    public void Arbitrarily_named_octet_schema_attributes_are_binary()
    {
        Assert.Equal(
            LdapValueKind.Binary,
            LdapAttributeSchema.KindFromSyntax("2.5.5.10", "4"));

        var bytes = new byte[] { 0, 1, 2, 255 };
        Assert.Same(bytes, SearchEntryReader.ConvertValue(bytes, LdapValueKind.Binary));
    }
}
