using System.Collections;
using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DictionaryMutationComparisonTests
{
    [Fact]
    public void Property_collection_dictionary_mutations_match_microsoft()
    {
        using var entry = new Ms.DirectoryEntry();
        IDictionary microsoft = entry.Properties;
        IDictionary ours = new Ours.PropertyCollection();

        Assert.Equal(ExerciseRejectedMutations(microsoft), ExerciseRejectedMutations(ours));
        Assert.All(
            ExerciseRejectedMutations(ours),
            exceptionType => Assert.Equal(typeof(NotSupportedException).FullName, exceptionType));
    }

    [Fact]
    public void Result_property_collection_dictionary_mutations_match_microsoft()
    {
        IDictionary microsoft = CreateMicrosoftResultProperties();
        IDictionary ours = new Ours.ResultPropertyCollection();

        var microsoftResult = ExerciseAllowedMutations(microsoft);
        var ourResult = ExerciseAllowedMutations(ours);

        Assert.Equal(microsoftResult, ourResult);
        Assert.Equal(new MutationResult(false, false, 1, 2, 1, 0), ourResult);
    }

    private static string?[] ExerciseRejectedMutations(IDictionary dictionary) =>
    [
        ExceptionType(() => dictionary.Add("added", "value")),
        ExceptionType(() => dictionary["assigned"] = "value"),
        ExceptionType(() => dictionary.Remove("missing")),
        ExceptionType(dictionary.Clear),
    ];

    private static MutationResult ExerciseAllowedMutations(IDictionary dictionary)
    {
        var isFixedSize = dictionary.IsFixedSize;
        var isReadOnly = dictionary.IsReadOnly;

        dictionary.Add("added", "value");
        var afterAdd = dictionary.Count;
        dictionary["assigned"] = "value";
        var afterAssignment = dictionary.Count;
        dictionary.Remove("added");
        var afterRemove = dictionary.Count;
        dictionary.Clear();

        return new MutationResult(
            isFixedSize,
            isReadOnly,
            afterAdd,
            afterAssignment,
            afterRemove,
            dictionary.Count);
    }

    private static IDictionary CreateMicrosoftResultProperties()
    {
        var constructor = typeof(Ms.ResultPropertyCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            Type.EmptyTypes,
            modifiers: null);

        Assert.NotNull(constructor);
        return Assert.IsAssignableFrom<IDictionary>(constructor.Invoke(null));
    }

    private static string? ExceptionType(Action action) =>
        Record.Exception(action)?.GetType().FullName;

    private sealed record MutationResult(
        bool IsFixedSize,
        bool IsReadOnly,
        int AfterAdd,
        int AfterAssignment,
        int AfterRemove,
        int AfterClear);
}
