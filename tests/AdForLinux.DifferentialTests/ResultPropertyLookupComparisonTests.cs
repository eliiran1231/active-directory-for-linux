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
        Assert.Equal(microsoft.Contains("DESCRIPTION"), ours.Contains("DESCRIPTION"));
        Assert.Equal(microsoft.Count, ours.Count);
        Assert.Same(expectedValue, ((IDictionary)microsoft)["description"]);
        Assert.Same(actualValue, ((IDictionary)ours)["description"]);

        Ms.ResultPropertyValueCollection? expected = null;
        Ours.ResultPropertyValueCollection? actual = null;
        var expectedError = Record.Exception(() => { expected = microsoft["DESCRIPTION"]; });
        var actualError = Record.Exception(() => { actual = ours["DESCRIPTION"]; });

        Assert.Equal(expectedError?.GetType(), actualError?.GetType());
        Assert.Equal(expected is null, actual is null);
        if (expected is not null)
        {
            Assert.Same(expectedValue, expected);
            Assert.Same(actualValue, actual);
            Assert.Equal(expected.Count, actual!.Count);
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
        Assert.Equal(microsoft.Count, ours.Count);

        // Reference identity is observable, including through ICollection.SyncRoot.
        Assert.Equal(
            ReferenceEquals(expectedFirst, expectedSecond),
            ReferenceEquals(actualFirst, actualSecond));
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
        Assert.Equal(microsoft.Contains("description"), ours.Contains("description"));
        Assert.Empty(microsoft["description"]);
        Assert.Empty(ours["description"]);
        Assert.Equal(microsoft.Count, ours.Count);
    }

    private static Ms.ResultPropertyCollection CreateMicrosoft()
    {
        var constructor = typeof(Ms.ResultPropertyCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.ResultPropertyCollection>(constructor.Invoke(null));
    }
}
