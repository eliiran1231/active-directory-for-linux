using System.Collections;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using static AdForLinux.DifferentialTests.NextBatchPrincipalStateComparisonTests;

namespace AdForLinux.DifferentialTests;

// Ordinary ExtensionSet uses a different clone translator from AdvancedFilterSet.
// These tests render the native Filter, without executing it or saving objects.
[Collection("differential")]
[Trait("Category", "CompatibilityNextBatchLive")]
public sealed class NextBatchExtensionQueryComparisonTests
{
    [Ms.DirectoryObjectClass("user")]
    private sealed class MicrosoftUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        internal void Write(object value) => ExtensionSet("description", value);
        internal object[] Read() => ExtensionGet("description");
    }

    [Ours.DirectoryObjectClass("user")]
    private sealed class OurUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        internal void Write(object value) => ExtensionSet("description", value);
        internal object?[] Read() => ExtensionGet("description");
    }

    [Theory]
    [InlineData("int-array")]
    [InlineData("array-list")]
    [InlineData("object-array")]
    [InlineData("scalar")]
    public void Ordinary_extension_query_preserves_collection_as_one_wrapped_value(string kind)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        using var expected = new MicrosoftUser(expectedContext);
        using var actual = new OurUser(actualContext);
        using var expectedSearcher = new Ms.PrincipalSearcher(expected);
        using var actualSearcher = new Ours.PrincipalSearcher(actual);
        var expectedValue = Input(kind);
        var actualValue = Input(kind);
        expected.Write(expectedValue);
        actual.Write(actualValue);
        if (kind is "int-array" or "array-list")
        {
            Assert.Same(expectedValue, Assert.Single(expected.Read()));
            Assert.Same(actualValue, Assert.Single(actual.Read()));
        }
        var comparison = new Comparison($"Ordinary ExtensionSet query: {kind}");
        CompareFilter("initial");
        expected.Write("replacement-control");
        actual.Write("replacement-control");
        CompareFilter("scalar replacement");
        comparison.Assert();

        void CompareFilter(string label)
        {
            var expectedFilter = Assert.IsType<System.DirectoryServices.DirectorySearcher>(expectedSearcher.GetUnderlyingSearcher()).Filter;
            string? actualFilter = null;
            var error = Record.Exception(() => actualFilter = Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(actualSearcher.GetUnderlyingSearcher()).Filter);
            Assert.Contains("description=", expectedFilter);
            comparison.Check($"{label}: exception", "success", Error(error))
                .Check($"{label}: filter", expectedFilter, actualFilter);
        }
    }

    private static object Input(string kind) => kind switch
    {
        "int-array" => new[] { 2, 5 },
        "array-list" => new ArrayList { "one", "two" },
        "object-array" => new object[] { "one", "two" },
        "scalar" => "one",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}
