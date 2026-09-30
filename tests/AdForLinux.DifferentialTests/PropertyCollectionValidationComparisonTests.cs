using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class PropertyCollectionValidationComparisonTests
{
    [Theory]
    [InlineData("typed-null")]
    [InlineData("dictionary-null")]
    [InlineData("dictionary-integer")]
    [InlineData("dictionary-object")]
    [InlineData("contains-integer")]
    [InlineData("contains-object")]
    public void Invalid_lookup_key_matches_microsoft(string operation)
    {
        // The Microsoft getter creates its collection without binding. These
        // invalid inputs are rejected before ADSI is accessed. Use our ordinary
        // internal constructor, as DictionaryMutationComparisonTests does,
        // because our DirectoryEntry.Properties getter would bind eagerly.
        using var entry = new Ms.DirectoryEntry();
        var microsoft = entry.Properties;
        var ours = new Ours.PropertyCollection();

        var expected = Record.Exception(() => Lookup(microsoft, operation));
        var actual = Record.Exception(() => Lookup(ours, operation));

        Assert.NotNull(expected);
        Assert.Equal(expected.GetType(), actual?.GetType());
        Assert.Equal((expected as ArgumentException)?.ParamName,
            (actual as ArgumentException)?.ParamName);
    }

    [Theory]
    [InlineData("negative-index")]
    [InlineData("null-array")]
    [InlineData("multidimensional-array")]
    public void CopyTo_validation_before_binding_matches_microsoft(string operation)
    {
        using var entry = new Ms.DirectoryEntry();
        ICollection microsoft = entry.Properties;
        ICollection ours = new Ours.PropertyCollection();
        Array? destination = operation switch
        {
            "negative-index" => new object[1],
            "null-array" => null,
            "multidimensional-array" => new object[1, 1],
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
        var index = operation == "negative-index" ? -1 : 0;

        var expected = Record.Exception(() => microsoft.CopyTo(destination!, index));
        var actual = Record.Exception(() => ours.CopyTo(destination!, index));

        Assert.NotNull(expected);
        Assert.Equal(expected.GetType(), actual?.GetType());
        Assert.Equal((expected as ArgumentException)?.ParamName,
            (actual as ArgumentException)?.ParamName);
    }

    private static void Lookup(Ms.PropertyCollection values, string operation)
    {
        if (operation == "typed-null")
            _ = values[null!];
        else
            Lookup((IDictionary)values, operation);
    }

    private static void Lookup(Ours.PropertyCollection values, string operation)
    {
        if (operation == "typed-null")
            _ = values[null!];
        else
            Lookup((IDictionary)values, operation);
    }

    private static void Lookup(IDictionary values, string operation)
    {
        object? key = operation switch
        {
            "dictionary-null" => null,
            "dictionary-integer" or "contains-integer" => 42,
            "dictionary-object" or "contains-object" => new object(),
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
        if (operation.StartsWith("contains-", StringComparison.Ordinal))
            _ = values.Contains(key!);
        else
            _ = values[key!];
    }
}
