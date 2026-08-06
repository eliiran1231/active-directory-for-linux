using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The values of one attribute in a <see cref="SearchResult"/>. Read-only,
/// like Microsoft's type. Typical use: <c>result.Properties["cn"][0]</c>.
/// </summary>
public sealed class ResultPropertyValueCollection : IEnumerable<object>
{
    private readonly IReadOnlyList<object> _values;

    internal ResultPropertyValueCollection(IReadOnlyList<object> values)
    {
        _values = values;
    }

    /// <summary>Gets the value at an index.</summary>
    public object this[int index] => _values[index];

    /// <summary>Number of values.</summary>
    public int Count => _values.Count;

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => _values.Contains(value);

    public IEnumerator<object> GetEnumerator() => _values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
