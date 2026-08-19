using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class CollectionBaseBehaviorComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public CollectionBaseBehaviorComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    [Fact]
    public void Property_value_inherited_mutations_and_exceptions_match()
    {
        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

        var microsoftResult = ExercisePropertyValues(microsoft.Properties["description"]);
        var ourResult = ExercisePropertyValues(ours.Properties["description"]);

        Assert.Equal(microsoftResult, ourResult);
    }

    [Fact]
    public void Result_value_inherited_copy_exceptions_match()
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        {
            SearchScope = Ms.SearchScope.Base,
            Filter = "(objectClass=*)",
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            SearchScope = Ours.SearchScope.Base,
            Filter = "(objectClass=*)",
        };
        microsoftSearcher.PropertiesToLoad.Add("description");
        ourSearcher.PropertiesToLoad.Add("description");

        var microsoftValues = microsoftSearcher.FindOne()!.Properties["description"];
        var ourValues = ourSearcher.FindOne()!.Properties["description"];

        Assert.IsAssignableFrom<ReadOnlyCollectionBase>(microsoftValues);
        Assert.IsAssignableFrom<ReadOnlyCollectionBase>(ourValues);
        Assert.Equal(ExerciseCopies(microsoftValues), ExerciseCopies(ourValues));
    }

    [Fact]
    public void Result_property_enumeration_key_casing_matches()
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoftSearcher = new Ms.DirectorySearcher(microsoftRoot)
        {
            SearchScope = Ms.SearchScope.Base,
            Filter = "(objectClass=*)",
        };
        using var ourSearcher = new Ours.DirectorySearcher(ourRoot)
        {
            SearchScope = Ours.SearchScope.Base,
            Filter = "(objectClass=*)",
        };
        microsoftSearcher.PropertiesToLoad.Add("sAMAccountName");
        ourSearcher.PropertiesToLoad.Add("sAMAccountName");

        var microsoftProperties = microsoftSearcher.FindOne()!.Properties;
        var ourProperties = ourSearcher.FindOne()!.Properties;

        var microsoftCasing = KeyCasing(
            microsoftProperties.PropertyNames,
            microsoftProperties.GetEnumerator(),
            "sAMAccountName");
        var ourCasing = KeyCasing(
            ourProperties.PropertyNames,
            ourProperties.GetEnumerator(),
            "sAMAccountName");

        Assert.Equal("samaccountname", microsoftCasing.PropertyName);
        Assert.Equal(microsoftCasing, ourCasing);
    }

    private static PropertyValueResult ExercisePropertyValues(Ms.PropertyValueCollection values)
    {
        values.Value = new object[] { "first", "second", "third" };
        var collection = Assert.IsAssignableFrom<CollectionBase>(values);
        collection.RemoveAt(1);
        var afterRemove = string.Join("|", values.Cast<object>());
        var invalidRemove = Record.Exception(() => collection.RemoveAt(-1))!.GetType().FullName;
        collection.Clear();
        return new PropertyValueResult(afterRemove, collection.Count, invalidRemove);
    }

    private static PropertyValueResult ExercisePropertyValues(Ours.PropertyValueCollection values)
    {
        values.Value = new object[] { "first", "second", "third" };
        var collection = Assert.IsAssignableFrom<CollectionBase>(values);
        collection.RemoveAt(1);
        var afterRemove = string.Join("|", values.Cast<object>());
        var invalidRemove = Record.Exception(() => collection.RemoveAt(-1))!.GetType().FullName;
        collection.Clear();
        return new PropertyValueResult(afterRemove, collection.Count, invalidRemove);
    }

    private static CopyResult ExerciseCopies(ICollection values)
    {
        var copy = new object[values.Count];
        values.CopyTo(copy, 0);
        return new CopyResult(
            string.Join("|", copy),
            ExceptionType(() => values.CopyTo(null!, 0)),
            ExceptionType(() => values.CopyTo(new object[Math.Max(0, values.Count - 1)], 0)),
            ExceptionType(() => values.CopyTo(new object[values.Count], -1)));
    }

    private static string ExceptionType(Action action) =>
        Record.Exception(action)?.GetType().FullName ?? string.Empty;

    private static KeyCasingResult KeyCasing(
        ICollection propertyNames,
        IDictionaryEnumerator enumerator,
        string requestedName)
    {
        var propertyName = Assert.Single(
            propertyNames.Cast<string>(),
            name => string.Equals(name, requestedName, StringComparison.OrdinalIgnoreCase));
        string? enumeratedKey = null;
        while (enumerator.MoveNext())
        {
            if (enumerator.Key is string key &&
                string.Equals(key, requestedName, StringComparison.OrdinalIgnoreCase))
            {
                enumeratedKey = key;
                break;
            }
        }

        return new KeyCasingResult(propertyName, Assert.IsType<string>(enumeratedKey));
    }

    private sealed record PropertyValueResult(
        string AfterRemove,
        int AfterClearCount,
        string? InvalidRemoveException);

    private sealed record CopyResult(
        string Values,
        string NullArrayException,
        string ShortArrayException,
        string NegativeIndexException);

    private sealed record KeyCasingResult(string PropertyName, string EnumeratorKey);
}
