using System.Collections;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class CollectionCompatibilityTests
{
    private enum SampleValue
    {
        First = 1,
        Second = 2,
    }

    [Fact]
    public void Property_values_track_ordered_add_delete_replace_and_clear_changes()
    {
        var values = new PropertyValueCollection("member");

        values.Add("CN=one");
        Assert.Collection(
            values.Changes,
            change => AssertChange(change, PropertyValueChangeType.Add, "CN=one"));

        values.ResetChanged();
        values.Remove("CN=not-in-the-downloaded-range");
        Assert.Collection(
            values.Changes,
            change => AssertChange(
                change,
                PropertyValueChangeType.Delete,
                "CN=not-in-the-downloaded-range"));

        values.ResetChanged();
        values.Value = new object[] { "CN=two", "CN=three" };
        Assert.Collection(
            values.Changes,
            change => AssertChange(
                change,
                PropertyValueChangeType.Replace,
                "CN=two",
                "CN=three"));

        values.Clear();
        Assert.Collection(
            values.Changes,
            change => AssertChange(change, PropertyValueChangeType.Clear));
    }

    [Fact]
    public void Indexed_replacement_uses_delete_and_add_for_multi_valued_properties()
    {
        var values = new PropertyValueCollection("member");
        values.AddLoaded("CN=one");
        values.AddLoaded("CN=two");

        values[1] = "CN=replacement";

        Assert.Collection(
            values.Changes,
            change => AssertChange(change, PropertyValueChangeType.Delete, "CN=two"),
            change => AssertChange(change, PropertyValueChangeType.Add, "CN=replacement"));
    }

    private static void AssertChange(
        PropertyValueChange change,
        PropertyValueChangeType expectedType,
        params object[] expectedValues)
    {
        Assert.Equal(expectedType, change.Type);
        Assert.Equal(expectedValues, change.Values);
    }

    [Fact]
    public void Schema_name_collection_supports_the_list_contract()
    {
        using var entry = new DirectoryEntry();
        var schemas = entry.Children.SchemaFilter;
        schemas.AddRange(new[] { "user", "group" });

        IList list = schemas;
        list.Insert(1, "computer");

        Assert.True(schemas.Contains("USER"));
        Assert.Equal(1, schemas.IndexOf("COMPUTER"));
        Assert.Equal(new[] { "user", "computer", "group" }, schemas.Cast<string>());

        var copy = new string[schemas.Count];
        schemas.CopyTo(copy, 0);
        Assert.Equal(new[] { "user", "computer", "group" }, copy);
    }

    [Fact]
    public void Property_collection_supports_dictionary_and_copy_contracts()
    {
        var properties = new PropertyCollection();
        properties["cn"].Add("Alice");

        IDictionary dictionary = properties;
        Assert.True(dictionary.Contains("CN"));
        Assert.True(dictionary.IsFixedSize);
        Assert.True(dictionary.IsReadOnly);
        Assert.Same(properties["cn"], dictionary["CN"]);
        Assert.Contains("cn", properties.PropertyNames.Cast<string>(), StringComparer.OrdinalIgnoreCase);
        Assert.Contains(properties["cn"], properties.Values.Cast<PropertyValueCollection>());

        var copy = new PropertyValueCollection[1];
        properties.CopyTo(copy, 0);
        Assert.Same(properties["cn"], copy[0]);

        ICollection collection = properties;
        var interfaceCopy = new PropertyValueCollection[properties.Count];
        collection.CopyTo(interfaceCopy, 0);
        Assert.Same(properties["cn"], interfaceCopy[0]);

        var enumerator = properties.GetEnumerator();
        Assert.True(enumerator.MoveNext());
        Assert.Same(properties["cn"], enumerator.Current);
        Assert.Equal("cn", (string)enumerator.Key, ignoreCase: true);

        Assert.Throws<NotSupportedException>(() => dictionary.Add("mail", properties["mail"]));
    }

    [Fact]
    public void Property_value_collection_supports_mutable_list_helpers()
    {
        var values = new PropertyValueCollection("member");
        values.AddRange(new object[] { "first", "third" });
        values.Insert(1, "second");
        values[2] = "last";

        IList list = values;
        list.Add("tail");

        Assert.Equal(1, values.IndexOf("second"));
        Assert.Equal(new object[] { "first", "second", "last", "tail" }, values.Cast<object>());

        var copy = new object[values.Count];
        values.CopyTo(copy, 0);
        Assert.Equal(values.Cast<object>(), copy);

        values.RemoveAt(3);
        Assert.Equal(3, values.Count);
        Assert.True(values.Changed);
    }

    [Fact]
    public void Collection_base_operations_preserve_property_value_deltas()
    {
        var values = new PropertyValueCollection("member");
        Assert.IsAssignableFrom<CollectionBase>(values);

        values.AddLoaded("first");
        values.AddLoaded("second");
        values.ResetChanged();

        values.RemoveAt(0);
        Assert.Collection(
            values.Changes,
            change => AssertChange(change, PropertyValueChangeType.Delete, "first"));

        values.Clear();
        Assert.Collection(
            values.Changes,
            change => AssertChange(change, PropertyValueChangeType.Clear));
    }

    [Fact]
    public void Property_value_expands_all_arrays_except_byte_arrays()
    {
        var values = new PropertyValueCollection("extensionAttribute");

        values.Value = new[] { 1, 2 };
        Assert.Equal(new object[] { 1, 2 }, values.Cast<object>());
        AssertChange(values.Changes.Single(), PropertyValueChangeType.Replace, 1, 2);

        values.Value = new long[] { 3, 4 };
        Assert.Equal(new object[] { 3L, 4L }, values.Cast<object>());

        values.Value = new[] { SampleValue.First, SampleValue.Second };
        Assert.Equal(
            new object[] { SampleValue.First, SampleValue.Second },
            values.Cast<object>());

        values.Value = new object[] { "five", 6 };
        Assert.Equal(new object[] { "five", 6 }, values.Cast<object>());

        var bytes = new byte[] { 7, 8 };
        values.Value = bytes;
        Assert.Single(values);
        Assert.Same(bytes, values[0]);
        AssertChange(values.Changes.Single(), PropertyValueChangeType.Replace, bytes);
    }

    [Fact]
    public void Property_value_lookup_and_removal_use_object_equality()
    {
        var bytes = new byte[] { 1, 2, 3 };
        var equalBytes = new byte[] { 1, 2, 3 };
        var values = new PropertyValueCollection("extensionAttribute");
        values.Value = new object[] { "CaseSensitive", bytes };
        values.ResetChanged();

        Assert.False(values.Contains("casesensitive"));
        Assert.Equal(-1, values.IndexOf("casesensitive"));
        values.Remove("casesensitive");
        Assert.Equal(2, values.Count);
        AssertChange(
            values.Changes.Single(),
            PropertyValueChangeType.Delete,
            "casesensitive");

        values.ResetChanged();
        Assert.False(values.Contains(equalBytes));
        Assert.Equal(-1, values.IndexOf(equalBytes));
        values.Remove(equalBytes);
        Assert.Equal(2, values.Count);
        AssertChange(values.Changes.Single(), PropertyValueChangeType.Delete, equalBytes);

        values.ResetChanged();
        Assert.True(values.Contains(bytes));
        Assert.Equal(1, values.IndexOf(bytes));
        values.Remove(bytes);
        Assert.Single(values);
    }

    [Fact]
    public void Result_property_collections_are_read_only_dictionary_and_collection_views()
    {
        var properties = new ResultPropertyCollection();
        properties.Set("sAMAccountName", new object[] { "Alice", "Alias" });

        Assert.IsAssignableFrom<DictionaryBase>(properties);
        Assert.IsAssignableFrom<ReadOnlyCollectionBase>(properties["samAccountName"]);

        IDictionary dictionary = properties;
        Assert.True(dictionary.Contains("SAMACCOUNTNAME"));
        Assert.True(dictionary.IsReadOnly);
        Assert.Single(properties);
        Assert.Equal(1, properties["samAccountName"].IndexOf("Alias"));
        Assert.Equal("samaccountname", Assert.Single(properties.PropertyNames.Cast<string>()));

        var enumerator = properties.GetEnumerator();
        Assert.True(enumerator.MoveNext());
        Assert.Equal("samaccountname", enumerator.Key);

        var values = new object[2];
        properties["samAccountName"].CopyTo(values, 0);
        Assert.Equal(new object[] { "Alice", "Alias" }, values);

        var collections = new ResultPropertyValueCollection[1];
        properties.CopyTo(collections, 0);
        Assert.Same(properties["samAccountName"], collections[0]);
        Assert.Throws<NotSupportedException>(() => dictionary.Clear());
    }

    [Fact]
    public void Search_result_collection_exposes_protocol_compatible_metadata_and_disposal()
    {
        var requested = new[] { "cn", "mail" };
        var results = new SearchResultCollection(Array.Empty<SearchResult>(), requested);

        requested[0] = "changed";
        Assert.Empty(results);
        Assert.Equal(new[] { "cn", "mail" }, results.PropertiesLoaded);
        Assert.Equal(IntPtr.Zero, results.Handle);
        Assert.IsAssignableFrom<ICollection>(results);

        results.Dispose();
        Assert.Throws<ObjectDisposedException>(() => results.Handle);
    }

    [Fact]
    public void Uncached_search_result_collection_is_forward_only_until_materialized()
    {
        var enumerations = 0;
        IEnumerable<SearchResult> Stream()
        {
            enumerations++;
            yield break;
        }

        using var results = new SearchResultCollection(Stream(), cacheResults: false);

        Assert.Empty(results.Cast<SearchResult>());
        Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(1, enumerations);
    }
}
