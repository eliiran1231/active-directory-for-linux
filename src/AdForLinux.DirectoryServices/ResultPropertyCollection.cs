using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The attributes of a <see cref="SearchResult"/>, keyed by name. Asking for a
/// missing attribute returns an empty collection, like Microsoft, so
/// <c>result.Properties["x"][0]</c> only throws when the attribute really is
/// absent (empty), not with a KeyNotFoundException.
/// </summary>
public class ResultPropertyCollection : DictionaryBase, IEnumerable<ResultPropertyValueCollection>
{
    private static readonly ResultPropertyValueCollection Empty =
        new(Array.Empty<object>());

    internal ResultPropertyCollection()
    {
    }

    // Microsoft normalizes result-property keys before placing them in its
    // DictionaryBase, so dictionary enumeration exposes lower-case names too.
    internal void Set(string name, IReadOnlyList<object> values) =>
        InnerHashtable[name.ToLowerInvariant()] = new ResultPropertyValueCollection(values);

    /// <summary>The values for an attribute, or an empty collection if absent.</summary>
    public ResultPropertyValueCollection this[string name] =>
        InnerHashtable[name.ToLowerInvariant()] is ResultPropertyValueCollection values ? values : Empty;

    /// <summary>True if the attribute is present in the result.</summary>
    public bool Contains(string propertyName) => InnerHashtable.Contains(propertyName.ToLowerInvariant());

    /// <summary>All attribute names in the result.</summary>
    public ICollection PropertyNames => InnerHashtable.Keys;

    /// <summary>All property value collections in the result.</summary>
    public ICollection Values => InnerHashtable.Values;

    /// <summary>Copies the property value collections to an array.</summary>
    public void CopyTo(ResultPropertyValueCollection[] array, int index) =>
        InnerHashtable.Values.CopyTo(array, index);

    IEnumerator<ResultPropertyValueCollection> IEnumerable<ResultPropertyValueCollection>.GetEnumerator() =>
        InnerHashtable.Values.Cast<ResultPropertyValueCollection>().GetEnumerator();
}
