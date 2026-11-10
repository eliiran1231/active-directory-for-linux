using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// No AD fixture: use the normal internal empty constructor, then exercise only
// public APIs. IDictionary mutation is supported by both implementations.
public sealed class ResultPropertyLookupComparisonTests
{
    [Theory]
    [InlineData("null")]
    [InlineData("string")]
    [InlineData("integer")]
    [InlineData("collection")]
    public void Typed_lookup_after_dictionary_assignment_matches_microsoft(string payload)
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.ResultPropertyCollection();
        object? expectedValue = payload switch
        {
            "null" => null,
            "string" => "unexpected value",
            "integer" => 42,
            "collection" => microsoft["missing"],
            _ => throw new ArgumentOutOfRangeException(nameof(payload)),
        };
        object? actualValue = payload == "collection" ? ours["missing"] : expectedValue;
        ((IDictionary)microsoft)["description"] = expectedValue;
        ((IDictionary)ours)["description"] = actualValue;

        Assert.True(microsoft.Contains("DESCRIPTION"));
        Assert.Equal(SuiteCapture.Expected(microsoft.Contains("DESCRIPTION"), "assert-equal-expected", 35), SuiteCapture.Expected(ours.Contains("DESCRIPTION"), "assert-equal-actual", 35));
        Assert.Equal(SuiteCapture.Expected(microsoft.Count, "assert-equal-expected", 36), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 36));
        Assert.Same(expectedValue, ((IDictionary)microsoft)["description"]);
        Assert.Same(actualValue, ((IDictionary)ours)["description"]);

        Ms.ResultPropertyValueCollection? expected = null;
        Ours.ResultPropertyValueCollection? actual = null;
        var expectedError = Record.Exception(() => { expected = microsoft["DESCRIPTION"]; });
        var actualError = Record.Exception(() => { actual = ours["DESCRIPTION"]; });

        Assert.Equal(SuiteCapture.Expected(expectedError?.GetType(), "assert-equal-expected", 45), SuiteCapture.Expected(actualError?.GetType(), "assert-equal-actual", 45));
        Assert.Equal(SuiteCapture.Expected(expected is null, "assert-equal-expected", 46), SuiteCapture.Expected(actual is null, "assert-equal-actual", 46));
        if (expected is not null)
        {
            Assert.Same(expectedValue, expected);
            Assert.Same(actualValue, actual);
            Assert.Equal(SuiteCapture.Expected(expected.Count, "assert-equal-expected", 51), SuiteCapture.Expected(actual!.Count, "assert-equal-actual", 51));
        }
    }

    [Theory]
    [InlineData("same-key")]
    [InlineData("different-key")]
    [InlineData("different-result")]
    public void Missing_property_collection_identity_matches_microsoft(string lookup)
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.ResultPropertyCollection();
        var otherMicrosoft = lookup == "different-result" ? CreateMicrosoft() : microsoft;
        var otherOurs = lookup == "different-result" ? new Ours.ResultPropertyCollection() : ours;
        var key = lookup == "different-key" ? "another-missing" : "missing";

        var expectedFirst = microsoft["missing"];
        var actualFirst = ours["missing"];
        var expectedSecond = otherMicrosoft[key];
        var actualSecond = otherOurs[key];

        Assert.Empty(expectedFirst);
        Assert.Empty(actualFirst);
        Assert.Empty(expectedSecond);
        Assert.Empty(actualSecond);
        Assert.False(microsoft.Contains("missing"));
        Assert.False(ours.Contains("missing"));
        Assert.Empty(microsoft);
        Assert.Equal(SuiteCapture.Expected(microsoft.Count, "assert-equal-expected", 79), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 79));

        // Reference identity is observable, including through ICollection.SyncRoot.
        Assert.Equal(
            SuiteCapture.Expected(ReferenceEquals(expectedFirst, expectedSecond), "assert-equal-expected", 82),
            SuiteCapture.Expected(ReferenceEquals(actualFirst, actualSecond), "assert-equal-actual", 82));
    }

    [Fact]
    public void Removed_property_returns_empty_collection_like_microsoft()
    {
        var microsoft = CreateMicrosoft();
        var ours = new Ours.ResultPropertyCollection();
        ((IDictionary)microsoft)["description"] = "temporary";
        ((IDictionary)ours)["description"] = "temporary";
        ((IDictionary)microsoft).Remove("description");
        ((IDictionary)ours).Remove("description");

        Assert.False(microsoft.Contains("description"));
        Assert.Equal(SuiteCapture.Expected(microsoft.Contains("description"), "assert-equal-expected", 98), SuiteCapture.Expected(ours.Contains("description"), "assert-equal-actual", 98));
        Assert.Empty(microsoft["description"]);
        Assert.Empty(ours["description"]);
        Assert.Equal(SuiteCapture.Expected(microsoft.Count, "assert-equal-expected", 101), SuiteCapture.Expected(ours.Count, "assert-equal-actual", 101));
    }

    private static Ms.ResultPropertyCollection CreateMicrosoft()
    {
        var constructor = typeof(Ms.ResultPropertyCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.ResultPropertyCollection>(constructor.Invoke(null));
    }
}
