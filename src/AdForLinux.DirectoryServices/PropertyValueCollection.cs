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
public sealed class PropertyValueCollection : IList, IEnumerable<object>
{
    private readonly List<object> _values = new();
    private readonly Action<PropertyValueCollection>? _onChanged;

    internal PropertyValueCollection(string propertyName, Action<PropertyValueCollection>? onChanged = null)
    {
        PropertyName = propertyName;
        _onChanged = onChanged;
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
    public object this[int index]
    {
        get => _values[index];
        set
        {
            _values[index] = value;
            MarkChanged();
        }
    }

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

            MarkChanged();
        }
    }

    /// <summary>Adds one value. Returns its index.</summary>
    public int Add(object value)
    {
        _values.Add(value);
        MarkChanged();
        return _values.Count - 1;
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(IEnumerable<object> values)
    {
        _values.AddRange(values);
        MarkChanged();
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(object[] values) => AddRange((IEnumerable<object>)values);

    /// <summary>Adds every value from another property collection.</summary>
    public void AddRange(PropertyValueCollection values)
    {
        ArgumentNullException.ThrowIfNull(values);
        AddRange(values._values);
    }

    /// <summary>Removes one value.</summary>
    public void Remove(object value)
    {
        var index = _values.FindIndex(v => ValueEquals(v, value));
        if (index >= 0)
        {
            _values.RemoveAt(index);
            MarkChanged();
        }
    }

    /// <summary>Appends a value read from the server, without marking it changed.</summary>
    internal void AddLoaded(object value) => _values.Add(value);

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => _values.Exists(v => ValueEquals(v, value));

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object[] array, int index) => _values.CopyTo(array, index);

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object value) => _values.FindIndex(v => ValueEquals(v, value));

    /// <summary>Inserts a value at the specified index.</summary>
    public void Insert(int index, object value)
    {
        _values.Insert(index, value);
        MarkChanged();
    }

    /// <summary>Removes the value at the specified index.</summary>
    public void RemoveAt(int index)
    {
        _values.RemoveAt(index);
        MarkChanged();
    }

    /// <summary>Removes every value.</summary>
    public void Clear()
    {
        _values.Clear();
        MarkChanged();
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

    private void MarkChanged()
    {
        Changed = true;
        _onChanged?.Invoke(this);
    }

    public IEnumerator<object> GetEnumerator() => _values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    bool IList.IsFixedSize => false;

    bool IList.IsReadOnly => false;

    object? IList.this[int index]
    {
        get => this[index];
        set => this[index] = value!;
    }

    int IList.Add(object? value) => Add(value!);

    bool IList.Contains(object? value) => value is not null && Contains(value);

    int IList.IndexOf(object? value) => value is not null ? IndexOf(value) : -1;

    void IList.Insert(int index, object? value) => Insert(index, value!);

    void IList.Remove(object? value)
    {
        if (value is not null)
        {
            Remove(value);
        }
    }

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index) => ((ICollection)_values).CopyTo(array, index);
}
