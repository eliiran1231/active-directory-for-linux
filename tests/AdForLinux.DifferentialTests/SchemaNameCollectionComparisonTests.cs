using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class SchemaNameCollectionComparisonTests
{
    [Fact]
    public void Add_contains_index_of_remove_and_indexer_assignment_match()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        Assert.Equal(ExerciseCollection(microsoft), ExerciseCollection(ours));
    }

    [Fact]
    public void Null_entries_and_casing_differences_match()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        Assert.Equal(ExerciseNullAndCasing(microsoft), ExerciseNullAndCasing(ours));
    }

    [Fact]
    public void Removing_a_missing_value_throws_the_same_exception()
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;

        AssertSameException(
            () => microsoft.Remove("missing"),
            () => ours.Remove("missing"));
    }

    [Theory]
    [InlineData("add", false)]
    [InlineData("add", true)]
    [InlineData("remove", false)]
    [InlineData("remove", true)]
    [InlineData("clear", false)]
    [InlineData("clear", true)]
    public void Enumerator_keeps_its_snapshot_after_structural_mutation(string mutation, bool started)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.AddRange(new[] { "user", "group", "computer" });
        ours.AddRange(new[] { "user", "group", "computer" });
        var microsoftEnumerator = microsoft.GetEnumerator();
        var ourEnumerator = ours.GetEnumerator();

        try
        {
            if (started)
            {
                Assert.True(microsoftEnumerator.MoveNext());
                Assert.True(ourEnumerator.MoveNext());
                Assert.Equal(microsoftEnumerator.Current, ourEnumerator.Current);
            }

            Mutate(microsoft, mutation);
            Mutate(ours, mutation);
            Assert.Equal(Snapshot(microsoft), Snapshot(ours));

            // Microsoft enumerates the array captured by GetEnumerator. A live
            // List<T> enumerator instead throws as soon as the collection changes.
            new Comparison($"SchemaNameCollection enumerator: {mutation}, started={started}")
                .Check("remaining values", ReadRemaining(microsoftEnumerator), ReadRemaining(ourEnumerator))
                .Assert();
        }
        finally
        {
            (microsoftEnumerator as IDisposable)?.Dispose();
            (ourEnumerator as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(1, false)]
    [InlineData(1, true)]
    public void Invalid_indexer_exception_type_matches_microsoft(int index, bool write)
    {
        var microsoft = CreateMicrosoftCollection();
        using var ourEntry = OurEntry();
        var ours = ourEntry.Children.SchemaFilter;
        microsoft.Add("user");
        ours.Add("user");

        var microsoftException = Record.Exception(() => AccessIndex(microsoft, index, write));
        var ourException = Record.Exception(() => AccessIndex(ours, index, write));

        Assert.Equal("user", Snapshot(microsoft));
        Assert.Equal(Snapshot(microsoft), Snapshot(ours));
        new Comparison($"SchemaNameCollection indexer: index={index}, write={write}")
            .Check("exception type", microsoftException?.GetType().FullName, ourException?.GetType().FullName)
            .Check("parameter", (microsoftException as ArgumentException)?.ParamName,
                (ourException as ArgumentException)?.ParamName)
            .Assert();
    }

    private static void AccessIndex(IList collection, int index, bool write)
    {
        if (write)
            collection[index] = "group";
        else
            _ = collection[index];
    }

    private static void Mutate(IList collection, string mutation)
    {
        switch (mutation)
        {
            case "add": collection.Add("organizationalUnit"); break;
            case "remove": collection.RemoveAt(1); break;
            case "clear": collection.Clear(); break;
            default: throw new ArgumentException("Unknown mutation", nameof(mutation));
        }
    }

    private static EnumerationResult ReadRemaining(IEnumerator enumerator)
    {
        var values = new List<string>();
        var exception = Record.Exception(() =>
        {
            while (enumerator.MoveNext())
                values.Add((string)enumerator.Current);
        });
        return new EnumerationResult(string.Join("|", values), exception?.GetType().FullName);
    }

    private sealed record EnumerationResult(string Values, string? ExceptionType);

    private static Ms.SchemaNameCollection CreateMicrosoftCollection()
    {
        // Microsoft's public collection can only be obtained from a bound ADSI
        // container. Supplying its internal getter/setter delegates lets these
        // collection-only differential tests run without an AD dependency.
        var constructor = Assert.Single(typeof(Ms.SchemaNameCollection).GetConstructors(
            BindingFlags.Instance | BindingFlags.NonPublic));
        var parameterTypes = constructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray();
        var state = new MicrosoftCollectionState();
        var getter = Delegate.CreateDelegate(parameterTypes[0], state, nameof(MicrosoftCollectionState.GetValue));
        var setter = Delegate.CreateDelegate(parameterTypes[1], state, nameof(MicrosoftCollectionState.SetValue));
        return (Ms.SchemaNameCollection)constructor.Invoke(new object[] { getter, setter });
    }

    private static Ours.DirectoryEntry OurEntry() => new();

    private static CollectionResult ExerciseCollection(Ms.SchemaNameCollection collection)
    {
        var firstIndex = collection.Add("user");
        var secondIndex = collection.Add("group");
        var containsUser = collection.Contains("user");
        var userIndex = collection.IndexOf("user");
        collection[secondIndex] = "computer";
        var assignedValue = collection[secondIndex];
        collection.Remove("user");
        return new(firstIndex, secondIndex, containsUser, userIndex, assignedValue, Snapshot(collection));
    }

    private static CollectionResult ExerciseCollection(Ours.SchemaNameCollection collection)
    {
        var firstIndex = collection.Add("user");
        var secondIndex = collection.Add("group");
        var containsUser = collection.Contains("user");
        var userIndex = collection.IndexOf("user");
        collection[secondIndex] = "computer";
        var assignedValue = collection[secondIndex];
        collection.Remove("user");
        return new(firstIndex, secondIndex, containsUser, userIndex, assignedValue, Snapshot(collection));
    }

    private static NullAndCasingResult ExerciseNullAndCasing(Ms.SchemaNameCollection collection)
    {
        collection.Add("user");
        var nullIndex = collection.Add(null);
        collection.Add("USER");
        collection[0] = null;
        return new(
            nullIndex,
            collection.Contains(null),
            collection.IndexOf(null),
            collection.Contains("user"),
            collection.Contains("USER"),
            collection.IndexOf("USER"),
            Snapshot(collection));
    }

    private static NullAndCasingResult ExerciseNullAndCasing(Ours.SchemaNameCollection collection)
    {
        collection.Add("user");
        var nullIndex = collection.Add(null);
        collection.Add("USER");
        collection[0] = null;
        return new(
            nullIndex,
            collection.Contains(null),
            collection.IndexOf(null),
            collection.Contains("user"),
            collection.Contains("USER"),
            collection.IndexOf("USER"),
            Snapshot(collection));
    }

    private static string Snapshot(IEnumerable collection) =>
        string.Join("|", collection.Cast<string?>().Select(value => value ?? "(null)"));

    private static void AssertSameException(Action microsoftAction, Action ourAction)
    {
        var microsoftException = Record.Exception(microsoftAction);
        var ourException = Record.Exception(ourAction);

        Assert.NotNull(microsoftException);
        Assert.NotNull(ourException);
        Assert.Equal(microsoftException.GetType(), ourException.GetType());
        Assert.Equal(
            (microsoftException as ArgumentException)?.ParamName,
            (ourException as ArgumentException)?.ParamName);
    }

    private sealed record CollectionResult(
        int FirstIndex,
        int SecondIndex,
        bool ContainsUser,
        int UserIndex,
        string? AssignedValue,
        string Values);

    private sealed record NullAndCasingResult(
        int NullIndex,
        bool ContainsNull,
        int NullPosition,
        bool ContainsLowerCase,
        bool ContainsUpperCase,
        int UpperCasePosition,
        string Values);

    private sealed class MicrosoftCollectionState
    {
        private object? _value;

        public object? GetValue() => _value;

        public void SetValue(object? value) => _value = value;
    }
}
