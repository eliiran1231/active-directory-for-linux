using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The values of one attribute on a <see cref="DirectoryEntry"/>.
/// Mirrors Microsoft's type: <see cref="Value"/> is null when empty, the single
/// value when there is one, or an <c>object[]</c> when there are several.
///
/// Values are strings for text attributes and <c>byte[]</c> for binary ones,
/// the same shapes S.DS.Protocols returns.
/// </summary>
public sealed class PropertyValueCollection : IEnumerable<object>
{
    private readonly List<object> _values = new();

    internal PropertyValueCollection(string propertyName)
    {
        PropertyName = propertyName;
    }

    /// <summary>The attribute name these values belong to.</summary>
    public string PropertyName { get; }

    /// <summary>Number of values.</summary>
    public int Count => _values.Count;

    /// <summary>Gets the value at an index.</summary>
    public object this[int index] => _values[index];

    /// <summary>
    /// The value in the shape Microsoft uses: null / single value / object[].
    /// Setting it replaces all current values.
    /// </summary>
    public object? Value
    {
        get => _values.Count switch
        {
            0 => null,
            1 => _values[0],
            _ => _values.ToArray(),
        };
        set
        {
            _values.Clear();
            if (value is null)
            {
                return;
            }

            if (value is object[] many)
            {
                _values.AddRange(many);
            }
            else
            {
                _values.Add(value);
            }
        }
    }

    /// <summary>Adds one value. Returns its index.</summary>
    public int Add(object value)
    {
        _values.Add(value);
        return _values.Count - 1;
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(IEnumerable<object> values) => _values.AddRange(values);

    /// <summary>Removes one value.</summary>
    public void Remove(object value)
    {
        var index = _values.FindIndex(v => ValueEquals(v, value));
        if (index >= 0)
        {
            _values.RemoveAt(index);
        }
    }

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => _values.Exists(v => ValueEquals(v, value));

    /// <summary>Removes every value.</summary>
    public void Clear() => _values.Clear();

    private static bool ValueEquals(object a, object b)
    {
        if (a is byte[] ba && b is byte[] bb)
        {
            return ba.AsSpan().SequenceEqual(bb);
        }

        if (a is string sa && b is string sb)
        {
            return string.Equals(sa, sb, StringComparison.OrdinalIgnoreCase);
        }

        return Equals(a, b);
    }

    public IEnumerator<object> GetEnumerator() => _values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
