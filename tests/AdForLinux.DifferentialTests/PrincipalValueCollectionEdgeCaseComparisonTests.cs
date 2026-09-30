using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Offline tests: only fixture construction uses reflection. All observations
// come from public APIs, with the referenced Microsoft assembly as the oracle.
public sealed class PrincipalValueCollectionEdgeCaseComparisonTests
{
    [Theory]
    [InlineData(true, 0, 0)]
    [InlineData(false, 0, 0)]
    [InlineData(true, 2, 2)]
    [InlineData(false, 2, 2)]
    [InlineData(true, 2, 1)] // Control: index is inside the destination.
    [InlineData(false, 2, 1)]
    public void Empty_copy_at_destination_boundary_matches_microsoft(
        bool generic, int length, int index)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        var expectedDestination = Enumerable.Repeat("sentinel", length).ToArray();
        var actualDestination = expectedDestination.ToArray();

        var expected = Record.Exception(() => Copy(microsoft, expectedDestination, index, generic));
        var actual = Record.Exception(() => Copy(ours, actualDestination, index, generic));

        Assert.Equal(expectedDestination, actualDestination);
        Assert.Equal(Describe(expected), Describe(actual));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Copy_with_null_array_and_negative_index_matches_validation_order(bool generic)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        microsoft.Add("first");
        ours.Add("first");

        var expected = Record.Exception(() => Copy(microsoft, null!, -1, generic));
        var actual = Record.Exception(() => Copy(ours, null!, -1, generic));

        Assert.Equal(Describe(expected), Describe(actual));
        Assert.Equal(microsoft.ToArray(), ours.ToArray());
    }

    [Theory]
    [InlineData("nonzero-lower-bound")]
    [InlineData("numeric-widening")]
    [InlineData("object-array")] // Control: ordinary boxing works in both.
    public void Non_generic_copy_matches_array_shape_and_conversion_behavior(string destination)
    {
        var microsoft = CreateMicrosoft<int>();
        var ours = new Ours.PrincipalValueCollection<int>();
        microsoft.Add(7);
        microsoft.Add(11);
        ours.Add(7);
        ours.Add(11);
        var expectedDestination = CreateDestination(destination);
        var actualDestination = CreateDestination(destination);
        var index = destination == "nonzero-lower-bound" ? 1 : 0;

        var expected = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedDestination, index));
        var actual = Record.Exception(() => ((ICollection)ours).CopyTo(actualDestination, index));

        // Include output even if one implementation threw after a partial copy.
        Assert.Equal(
            (Describe(expected), Values(expectedDestination)),
            (Describe(actual), Values(actualDestination)));
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(1, false)]
    [InlineData(-1, true)] // Controls: IList validates null before the index.
    [InlineData(1, true)]
    [InlineData(0, false)] // Control: valid index with null value.
    public void Null_indexer_assignment_matches_validation_order(int index, bool nonGeneric)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        microsoft.Add("first");
        ours.Add("first");

        var expected = Record.Exception(() => SetNull(microsoft, index, nonGeneric));
        var actual = Record.Exception(() => SetNull(ours, index, nonGeneric));

        Assert.Equal(microsoft.ToArray(), ours.ToArray());
        Assert.Equal(Describe(expected), Describe(actual));
    }

    [Theory]
    [InlineData("add", "Current")]
    [InlineData("replace", "Current")]
    [InlineData("remove-missing", "MoveNext")]
    [InlineData("remove-missing", "Reset")]
    [InlineData("invalid-insert", "MoveNext")]
    [InlineData("invalid-remove-at", "MoveNext")]
    [InlineData("null-insert", "MoveNext")]
    [InlineData("null-replace", "MoveNext")]
    [InlineData("contains", "Current")] // Controls: reads preserve enumerators.
    [InlineData("contains", "MoveNext")]
    [InlineData("add", "MoveNext")] // Control: both reject structural changes.
    public void Enumerator_after_mutation_attempt_matches_microsoft(string mutation, string operation)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        foreach (var value in new[] { "first", "second" })
        {
            microsoft.Add(value);
            ours.Add(value);
        }

        using var expectedEnumerator = microsoft.GetEnumerator();
        using var actualEnumerator = ours.GetEnumerator();
        Assert.True(expectedEnumerator.MoveNext());
        Assert.True(actualEnumerator.MoveNext());
        Assert.Equal(expectedEnumerator.Current, actualEnumerator.Current);

        // Microsoft's change tracking compares DateTime.UtcNow timestamps.
        // Cross a clock tick explicitly so fast machines do not hide mutations.
        var afterConstruction = DateTime.UtcNow;
        Assert.True(SpinWait.SpinUntil(() => DateTime.UtcNow > afterConstruction, TimeSpan.FromSeconds(2)),
            "The clock must advance before exercising timestamp-based change tracking.");

        var expectedMutation = Record.Exception(() => Mutate(microsoft, mutation));
        var actualMutation = Record.Exception(() => Mutate(ours, mutation));
        Assert.Equal(Describe(expectedMutation), Describe(actualMutation));
        Assert.Equal(microsoft.ToArray(), ours.ToArray());

        Assert.Equal(Observe(expectedEnumerator, operation), Observe(actualEnumerator, operation));
    }

    private static void Copy(IList<string> values, string[] array, int index, bool generic)
    {
        if (generic) values.CopyTo(array, index);
        else ((ICollection)values).CopyTo(array, index);
    }

    private static Array CreateDestination(string kind) => kind switch
    {
        "nonzero-lower-bound" => Array.CreateInstance(typeof(int), new[] { 3 }, new[] { 1 }),
        "numeric-widening" => new long[2],
        "object-array" => new object[2],
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string Values(Array array) => string.Join(",", array.Cast<object?>());

    private static void SetNull(IList<string> values, int index, bool nonGeneric)
    {
        if (nonGeneric) ((IList)values)[index] = null;
        else values[index] = null!;
    }

    private static void Mutate(IList<string> values, string operation)
    {
        switch (operation)
        {
            case "add": values.Add("third"); break;
            case "replace": values[0] = "replacement"; break;
            case "remove-missing": Assert.False(values.Remove("absent")); break;
            case "invalid-insert": values.Insert(-1, "third"); break;
            case "invalid-remove-at": values.RemoveAt(-1); break;
            case "null-insert": values.Insert(0, null!); break;
            case "null-replace": values[0] = null!; break;
            case "contains": Assert.True(values.Contains("first")); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static (string? Error, string? Value) Observe(IEnumerator<string> enumerator, string operation)
    {
        string? value = null;
        var error = Record.Exception(() =>
        {
            switch (operation)
            {
                case "Current": value = enumerator.Current; break;
                case "MoveNext": value = enumerator.MoveNext().ToString(); break;
                case "Reset": enumerator.Reset(); value = "reset"; break;
                default: throw new ArgumentOutOfRangeException(nameof(operation));
            }
        });
        return (Describe(error), value);
    }

    private static string? Describe(Exception? error) => error is null
        ? null
        : $"{error.GetType().FullName}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";

    private static Ms.PrincipalValueCollection<T> CreateMicrosoft<T>()
    {
        // Same normal internal constructor used by the existing offline suite;
        // no fabricated PrincipalContext, uninitialized object, or field edits.
        var constructor = typeof(Ms.PrincipalValueCollection<T>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<T>>(constructor.Invoke(null));
    }
}
