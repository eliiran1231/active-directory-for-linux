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
    private readonly List<PropertyValueChange> _changes = new();
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
    internal bool Changed => _changes.Count != 0;

    /// <summary>The ordered LDAP changes staged since the last load or commit.</summary>
    internal IReadOnlyList<PropertyValueChange> Changes => _changes;

    /// <summary>Clears staged changes after a successful commit or load.</summary>
    internal void ResetChanged() => _changes.Clear();

    /// <summary>Number of values.</summary>
    public int Count => _values.Count;

    /// <summary>Gets the value at an index.</summary>
    public object this[int index]
    {
        get => _values[index];
        set
        {
            var oldValue = _values[index];
            _values[index] = value;
            if (_values.Count <= 1)
            {
                RecordChange(PropertyValueChangeType.Replace, _values);
            }
            else
            {
                RecordChange(PropertyValueChangeType.Delete, new[] { oldValue });
                RecordChange(PropertyValueChangeType.Add, new[] { value });
            }
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
            if (value is byte[] bytes)
            {
                _values.Add(bytes);
            }
            else if (value is Array array)
            {
                // Match ADSI: every array except byte[] represents multiple
                // attribute values. Array.CopyTo boxes value-type elements.
                var many = new object[array.Length];
                array.CopyTo(many, 0);
                _values.AddRange(many);
            }
            else if (value is not null)
            {
                _values.Add(value);
            }

            RecordChange(
                _values.Count == 0 ? PropertyValueChangeType.Clear : PropertyValueChangeType.Replace,
                _values);
        }
    }

    /// <summary>Adds one value. Returns its index.</summary>
    public int Add(object value)
    {
        _values.Add(value);
        RecordChange(PropertyValueChangeType.Add, new[] { value });
        return _values.Count - 1;
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(IEnumerable<object> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        foreach (var value in values)
        {
            Add(value);
        }
    }

    /// <summary>Adds several values.</summary>
    public void AddRange(object[] values) => AddRange((IEnumerable<object>)values);

    /// <summary>Adds every value from another property collection.</summary>
    public void AddRange(PropertyValueCollection values)
    {
        ArgumentNullException.ThrowIfNull(values);
        AddRange(values._values.ToArray());
    }

    /// <summary>Removes one value.</summary>
    public void Remove(object value)
    {
        var index = _values.IndexOf(value);
        if (index >= 0)
        {
            _values.RemoveAt(index);
        }

        // ADSI still stages a single-value delete when a value is absent from
        // the local cache. Active Directory may have withheld it in a later
        // range of a large multi-valued attribute.
        RecordChange(PropertyValueChangeType.Delete, new[] { value });
    }

    /// <summary>Appends a value read from the server, without marking it changed.</summary>
    internal void AddLoaded(object value) => _values.Add(value);

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => _values.Contains(value);

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object[] array, int index) => _values.CopyTo(array, index);

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object value) => _values.IndexOf(value);

    /// <summary>Inserts a value at the specified index.</summary>
    public void Insert(int index, object value)
    {
        _values.Insert(index, value);
        RecordChange(PropertyValueChangeType.Add, new[] { value });
    }

    /// <summary>Removes the value at the specified index.</summary>
    public void RemoveAt(int index)
    {
        var value = _values[index];
        _values.RemoveAt(index);
        RecordChange(PropertyValueChangeType.Delete, new[] { value });
    }

    /// <summary>Removes every value.</summary>
    public void Clear()
    {
        _values.Clear();
        RecordChange(PropertyValueChangeType.Clear, Array.Empty<object>());
    }

    private void RecordChange(PropertyValueChangeType type, IEnumerable<object> values)
    {
        // A whole-attribute operation supersedes every earlier pending delta.
        // This also prevents a stale Add/Delete from making an intentional
        // replacement fail before LDAP reaches the replacement operation.
        if (type is PropertyValueChangeType.Replace or PropertyValueChangeType.Clear)
        {
            _changes.Clear();
        }

        _changes.Add(new PropertyValueChange(type, values.ToArray()));
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

internal enum PropertyValueChangeType
{
    Add,
    Delete,
    Replace,
    Clear,
}

internal sealed record PropertyValueChange(PropertyValueChangeType Type, object[] Values);
