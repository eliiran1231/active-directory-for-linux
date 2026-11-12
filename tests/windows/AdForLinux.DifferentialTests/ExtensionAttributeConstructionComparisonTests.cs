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
        Assert.Equal(SuiteCapture.Expected(value, "assert-equal-expected", 46), SuiteCapture.Expected(expectedValue, "assert-equal-actual", 46));
        Assert.Equal(SuiteCapture.Expected(expectedError?.GetType(), "assert-equal-expected", 47), SuiteCapture.Expected(actualError?.GetType(), "assert-equal-actual", 47));
        Assert.Equal(SuiteCapture.Expected(expectedValue, "assert-equal-expected", 48), SuiteCapture.Expected(actualValue, "assert-equal-actual", 48));
    }
}
