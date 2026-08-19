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
