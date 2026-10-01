using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DirectoryEntryDisposedWrapperComparisonTests
{
    [Theory]
    [InlineData(false, "collection")]
    [InlineData(false, "names")]
    [InlineData(false, "values")]
    [InlineData(false, "read-only")]
    [InlineData(false, "null-key")]
    [InlineData(true, "collection")]
    [InlineData(true, "names")]
    [InlineData(true, "values")]
    [InlineData(true, "read-only")]
    [InlineData(true, "null-key")]
    public void Property_wrapper_access_after_dispose_matches_microsoft(bool primeWrapper, string operation)
    {
        using var microsoft = new Ms.DirectoryEntry();
        using var ours = new Ours.DirectoryEntry();
        if (primeWrapper)
        {
            _ = microsoft.Properties;
            _ = ours.Properties;
        }

        microsoft.Dispose();
        ours.Dispose();
        object? expected = null;
        object? actual = null;
        var expectedError = Record.Exception(() => expected = Observe(microsoft.Properties, operation));
        var actualError = Record.Exception(() => actual = Observe(ours.Properties, operation));

        // These operations never require attribute values or an ADSI binding.
        if (operation == "null-key")
            Assert.IsType<ArgumentNullException>(expectedError);
        else
            Assert.Null(expectedError);

        new Comparison($"Disposed Properties: primed={primeWrapper}, operation={operation}")
            .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
            .Check("parameter", (expectedError as ArgumentException)?.ParamName,
                (actualError as ArgumentException)?.ParamName)
            .Check("result", expected, actual)
            .Assert();
    }

    [Fact]
    public void Close_replaces_property_wrapper_without_disposing_entry_as_a_control()
    {
        using var microsoft = new Ms.DirectoryEntry();
        using var ours = new Ours.DirectoryEntry();
        var expectedOld = microsoft.Properties;
        var actualOld = ours.Properties;
        microsoft.Close();
        ours.Close();
        Assert.NotSame(expectedOld, microsoft.Properties);
        Assert.NotSame(actualOld, ours.Properties);
        Assert.Equal(((IDictionary)microsoft.Properties).IsReadOnly, ((IDictionary)ours.Properties).IsReadOnly);
    }

    private static object? Observe(Ms.PropertyCollection properties, string operation) => operation switch
    {
        "collection" => properties is not null,
        "names" => properties.PropertyNames is not null,
        "values" => properties.Values is not null,
        "read-only" => ((IDictionary)properties).IsReadOnly,
        "null-key" => properties[null!],
        _ => throw new ArgumentOutOfRangeException(nameof(operation)),
    };

    private static object? Observe(Ours.PropertyCollection properties, string operation) => operation switch
    {
        "collection" => properties is not null,
        "names" => properties.PropertyNames is not null,
        "values" => properties.Values is not null,
        "read-only" => ((IDictionary)properties).IsReadOnly,
        "null-key" => properties[null!],
        _ => throw new ArgumentOutOfRangeException(nameof(operation)),
    };
}
