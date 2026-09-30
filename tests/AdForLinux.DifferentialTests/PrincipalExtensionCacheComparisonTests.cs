using System.Collections;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Expose the supported subclass extension API through normal protected
// constructors. No context, private-field mutation, or directory is involved.
public sealed class PrincipalExtensionCacheComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal
    {
        public object[] Read(string attribute) => ExtensionGet(attribute);
        public void Write(string attribute, object? value) => ExtensionSet(attribute, value!);
    }

    private sealed class OurPrincipal : Ours.Principal
    {
        public object?[] Read(string attribute) => ExtensionGet(attribute);
        public void Write(string attribute, object? value) => ExtensionSet(attribute, value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Mutating_the_supplied_array_changes_cached_values_like_microsoft(bool stringArray)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        object[] expectedInput = stringArray ? new string[] { "one", "two" } : new object[] { "one", "two" };
        object[] actualInput = stringArray ? new string[] { "one", "two" } : new object[] { "one", "two" };
        microsoft.Write("otherTelephone", expectedInput);
        ours.Write("otherTelephone", actualInput);
        Assert.Equal(microsoft.Read("otherTelephone"), ours.Read("otherTelephone"));

        expectedInput[0] = actualInput[0] = "changed";

        Assert.Equal(microsoft.Read("otherTelephone"), ours.Read("otherTelephone"));
    }

    [Theory]
    [InlineData("array")]
    [InlineData("scalar")]
    [InlineData("null")]
    public void Mutating_a_returned_array_changes_cached_values_like_microsoft(string kind)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        microsoft.Write("description", Value(kind));
        ours.Write("description", Value(kind));
        var expected = microsoft.Read("description");
        var actual = ours.Read("description");
        Assert.Equal(expected, actual);

        expected[0] = actual[0] = "changed";

        Assert.Equal(microsoft.Read("description"), ours.Read("description"));
    }

    [Theory]
    [InlineData("description")] // Exact spelling is a control.
    [InlineData("Description")]
    [InlineData("DESCRIPTION")]
    public void Attribute_spelling_has_the_same_cache_lookup_and_replacement_behavior(string attribute)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        microsoft.Write("description", "original");
        ours.Write("description", "original");
        microsoft.Write(attribute, "replacement");
        ours.Write(attribute, "replacement");

        // Compare both keys together so a collision cannot hide behind a
        // successful read of the most recently assigned spelling.
        Assert.Equal(
            new[] { microsoft.Read("description"), microsoft.Read(attribute) },
            new[] { ours.Read("description"), ours.Read(attribute) });
    }

    [Theory]
    [InlineData("cached-read")]
    [InlineData("missing-read")]
    [InlineData("write")]
    public void Extension_cache_operations_after_disposal_match_microsoft(string operation)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        microsoft.Write("description", "original");
        ours.Write("description", "original");
        microsoft.Dispose();
        ours.Dispose();
        object?[]? expectedValues = null;
        object?[]? actualValues = null;

        var expected = Record.Exception(() =>
        {
            if (operation == "write") microsoft.Write("description", "replacement");
            expectedValues = microsoft.Read(operation == "missing-read" ? "missing" : "description");
        });
        var actual = Record.Exception(() =>
        {
            if (operation == "write") ours.Write("description", "replacement");
            actualValues = ours.Read(operation == "missing-read" ? "missing" : "description");
        });

        Assert.Equal(Describe(expected), Describe(actual));
        Assert.Equal(expectedValues, actualValues);
    }

    [Theory]
    [InlineData("null-read")]
    [InlineData("null-write")]
    [InlineData("empty-array")]
    [InlineData("empty-bytes")]
    [InlineData("empty-list")]
    [InlineData("nested-array")]
    public void Rejected_extension_arguments_match_exception_parameter_and_preserve_cache(string kind)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        microsoft.Write("description", "original");
        ours.Write("description", "original");
        var expected = Record.Exception(() =>
        {
            if (kind == "null-read") _ = microsoft.Read(null!);
            else microsoft.Write(kind == "null-write" ? null! : "description", Value(kind));
        });
        var actual = Record.Exception(() =>
        {
            if (kind == "null-read") _ = ours.Read(null!);
            else ours.Write(kind == "null-write" ? null! : "description", Value(kind));
        });

        Assert.Equal(microsoft.Read("description"), ours.Read("description"));
        Assert.IsType<ArgumentException>(expected);
        Assert.Equal(Describe(expected), Describe(actual));
    }

    private static object? Value(string kind) => kind switch
    {
        "array" => new object[] { "original" },
        "scalar" or "null-write" => "original",
        "null" => null,
        "empty-array" => Array.Empty<object>(),
        "empty-bytes" => Array.Empty<byte>(),
        "empty-list" => new ArrayList(),
        "nested-array" => new object[] { new object[] { "nested" } },
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string Describe(Exception? exception) => exception is null
        ? "accepted"
        : $"{exception.GetType().FullName}; ParamName={(exception as ArgumentException)?.ParamName ?? "<null>"}";
}
