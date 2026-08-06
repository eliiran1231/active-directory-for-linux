using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The attributes of a <see cref="SearchResult"/>, keyed by name. Asking for a
/// missing attribute returns an empty collection, like Microsoft, so
/// <c>result.Properties["x"][0]</c> only throws when the attribute really is
/// absent (empty), not with a KeyNotFoundException.
/// </summary>
public sealed class ResultPropertyCollection : IEnumerable<ResultPropertyValueCollection>
{
    private static readonly ResultPropertyValueCollection Empty =
        new(Array.Empty<object>());

    private readonly Dictionary<string, ResultPropertyValueCollection> _byName =
        new(StringComparer.OrdinalIgnoreCase);

    internal ResultPropertyCollection()
    {
    }

    internal void Set(string name, IReadOnlyList<object> values) =>
        _byName[name] = new ResultPropertyValueCollection(values);

    /// <summary>The values for an attribute, or an empty collection if absent.</summary>
    public ResultPropertyValueCollection this[string propertyName] =>
        _byName.TryGetValue(propertyName, out var values) ? values : Empty;

    /// <summary>True if the attribute is present in the result.</summary>
    public bool Contains(string propertyName) => _byName.ContainsKey(propertyName);

    /// <summary>All attribute names in the result.</summary>
    public ICollection<string> PropertyNames => _byName.Keys;

    /// <summary>Number of distinct attributes.</summary>
    public int Count => _byName.Count;

    public IEnumerator<ResultPropertyValueCollection> GetEnumerator() => _byName.Values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
