using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The attributes of a <see cref="SearchResult"/>, keyed by name. Asking for a
/// missing attribute returns an empty collection, like Microsoft, so
/// <c>result.Properties["x"][0]</c> only throws when the attribute really is
/// absent (empty), not with a KeyNotFoundException.
/// </summary>
public sealed class ResultPropertyCollection : DictionaryBase, IDictionary, IEnumerable<ResultPropertyValueCollection>
{
    private static readonly ResultPropertyValueCollection Empty =
        new(Array.Empty<object>());

    internal ResultPropertyCollection()
    {
    }

    internal void Set(string name, IReadOnlyList<object> values) =>
        InnerHashtable[name.ToLowerInvariant()] = new ResultPropertyValueCollection(values);

    /// <summary>The values for an attribute, or an empty collection if absent.</summary>
    public ResultPropertyValueCollection this[string propertyName] =>
        InnerHashtable[propertyName.ToLowerInvariant()] is ResultPropertyValueCollection values ? values : Empty;

    /// <summary>True if the attribute is present in the result.</summary>
    public bool Contains(string propertyName) => InnerHashtable.Contains(propertyName.ToLowerInvariant());

    /// <summary>All attribute names in the result.</summary>
    public ICollection PropertyNames => InnerHashtable.Keys;

    /// <summary>All property value collections in the result.</summary>
    public ICollection Values => InnerHashtable.Values;

    /// <summary>Copies the property value collections to an array.</summary>
    public void CopyTo(ResultPropertyValueCollection[] array, int index) =>
        InnerHashtable.Values.CopyTo(array, index);

    public new IDictionaryEnumerator GetEnumerator() => InnerHashtable.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<ResultPropertyValueCollection> IEnumerable<ResultPropertyValueCollection>.GetEnumerator() =>
        InnerHashtable.Values.Cast<ResultPropertyValueCollection>().GetEnumerator();

    bool IDictionary.IsFixedSize => true;

    bool IDictionary.IsReadOnly => true;

    ICollection IDictionary.Keys => PropertyNames;

    ICollection IDictionary.Values => Values;

    object? IDictionary.this[object key]
    {
        get => key is string name ? this[name] : null;
        set => throw new NotSupportedException("Search result properties are read-only.");
    }

    void IDictionary.Add(object key, object? value) =>
        throw new NotSupportedException("Search result properties are read-only.");

    void IDictionary.Clear() => throw new NotSupportedException("Search result properties are read-only.");

    bool IDictionary.Contains(object key) => key is string name && Contains(name);

    IDictionaryEnumerator IDictionary.GetEnumerator() => GetEnumerator();

    void IDictionary.Remove(object key) =>
        throw new NotSupportedException("Search result properties are read-only.");

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index) => InnerHashtable.CopyTo(array, index);
}
