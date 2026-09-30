using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Attribute construction is entirely offline and uses only public APIs.
public sealed class ExtensionAttributeConstructionComparisonTests
{
    [Theory]
    [InlineData("property", null)]
    [InlineData("rdn", null)]
    [InlineData("class", null)]
    [InlineData("property", "")]
    [InlineData("rdn", "")]
    [InlineData("class", "")]
    [InlineData("property", "description")]
    [InlineData("rdn", "CN")]
    [InlineData("class", "user")]
    public void Constructor_preserves_the_same_value(string attribute, string? value)
    {
        string? expectedValue = null;
        string? actualValue = null;
        var expectedError = Record.Exception(() =>
        {
            expectedValue = attribute switch
            {
                "property" => new Ms.DirectoryPropertyAttribute(value!).SchemaAttributeName,
                "rdn" => new Ms.DirectoryRdnPrefixAttribute(value!).RdnPrefix,
                "class" => new Ms.DirectoryObjectClassAttribute(value!).ObjectClass,
                _ => throw new ArgumentOutOfRangeException(nameof(attribute)),
            };
        });
        var actualError = Record.Exception(() =>
        {
            actualValue = attribute switch
            {
                "property" => new Ours.DirectoryPropertyAttribute(value!).SchemaAttributeName,
                "rdn" => new Ours.DirectoryRdnPrefixAttribute(value!).RdnPrefix,
                "class" => new Ours.DirectoryObjectClassAttribute(value!).ObjectClass,
                _ => throw new ArgumentOutOfRangeException(nameof(attribute)),
            };
        });

        Assert.Null(expectedError);
        Assert.Equal(value, expectedValue);
        Assert.Equal(expectedError?.GetType(), actualError?.GetType());
        Assert.Equal(expectedValue, actualValue);
    }
}
