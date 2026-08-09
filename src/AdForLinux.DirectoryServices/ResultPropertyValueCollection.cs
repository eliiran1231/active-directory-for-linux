using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The values of one attribute in a <see cref="SearchResult"/>. Read-only,
/// like Microsoft's type. Typical use: <c>result.Properties["cn"][0]</c>.
/// </summary>
public sealed class ResultPropertyValueCollection : ICollection, IEnumerable<object>
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

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object[] array, int index)
    {
        for (var i = 0; i < _values.Count; i++)
        {
            array[index + i] = _values[i];
        }
    }

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object value)
    {
        for (var i = 0; i < _values.Count; i++)
        {
            if (Equals(_values[i], value))
            {
                return i;
            }
        }

        return -1;
    }

    public IEnumerator<object> GetEnumerator() => _values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index)
    {
        for (var i = 0; i < _values.Count; i++)
        {
            array.SetValue(_values[i], index + i);
        }
    }
}
