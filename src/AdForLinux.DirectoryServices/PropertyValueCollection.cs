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

    /// <summary>
    /// True once the values were changed since the last load or commit. The
    /// entry uses this to know what to send on CommitChanges.
    /// </summary>
    internal bool Changed { get; private set; }

    /// <summary>Clears the changed flag after a successful commit or load.</summary>
    internal void ResetChanged() => Changed = false;

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
            if (value is object[] many)
            {
                _values.AddRange(many);
            }
            else if (value is not null)
            {
                _values.Add(value);
            }

            Changed = true;
        }
    }

    /// <summary>Adds one value. Returns its index.</summary>
    public int Add(object value)
    {
        _values.Add(value);
        Changed = true;
        return _values.Count - 1;
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(IEnumerable<object> values)
    {
        _values.AddRange(values);
        Changed = true;
    }

    /// <summary>Removes one value.</summary>
    public void Remove(object value)
    {
        var index = _values.FindIndex(v => ValueEquals(v, value));
        if (index >= 0)
        {
            _values.RemoveAt(index);
            Changed = true;
        }
    }

    /// <summary>Appends a value read from the server, without marking it changed.</summary>
    internal void AddLoaded(object value) => _values.Add(value);

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => _values.Exists(v => ValueEquals(v, value));

    /// <summary>Removes every value.</summary>
    public void Clear()
    {
        _values.Clear();
        Changed = true;
    }

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
