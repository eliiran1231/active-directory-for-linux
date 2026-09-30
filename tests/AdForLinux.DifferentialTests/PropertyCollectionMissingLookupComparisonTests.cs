using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyCollectionMissingLookupComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public PropertyCollectionMissingLookupComparisonTests(TestDataFixture data) => _data = data;

    [Theory]
    [InlineData("Contains")]
    [InlineData("Count")]
    [InlineData("PropertyNames")]
    public void Reading_an_absent_property_does_not_add_it_to_the_property_list(string observation)
    {
        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        var expected = microsoft.Properties;
        var actual = ours.Properties;
        const string missing = "adflNonexistentCompatibilityAttribute";

        Assert.False(expected.Contains(missing));
        Assert.False(actual.Contains(missing));
        var expectedCount = expected.Count;
        var actualCount = actual.Count;
        var expectedNames = Names(expected.PropertyNames);
        var actualNames = Names(actual.PropertyNames);

        // Public read only: neither entry is edited or committed. Microsoft's
        // value cache and provider property list are separate collections.
        Assert.Empty(expected[missing]);
        Assert.Empty(actual[missing]);
        Assert.Null(expected[missing].Value);
        Assert.Null(actual[missing].Value);

        switch (observation)
        {
            case "Contains":
                Assert.False(expected.Contains(missing));
                Assert.Equal(expected.Contains(missing), actual.Contains(missing));
                break;
            case "Count":
                Assert.Equal(expectedCount, expected.Count);
                // Compare deltas so unrelated provider projection differences
                // cannot produce a false positive for this lookup regression.
                Assert.Equal(expected.Count - expectedCount, actual.Count - actualCount);
                break;
            case "PropertyNames":
                Assert.Equal(expectedNames, Names(expected.PropertyNames));
                Assert.Equal(
                    Names(expected.PropertyNames).Except(expectedNames).ToArray(),
                    Names(actual.PropertyNames).Except(actualNames).ToArray());
                break;
            default: throw new ArgumentOutOfRangeException(nameof(observation));
        }
    }

    private static string[] Names(ICollection names) => names.Cast<string>()
        .Select(name => name.ToLowerInvariant()).Order(StringComparer.Ordinal).ToArray();
}
