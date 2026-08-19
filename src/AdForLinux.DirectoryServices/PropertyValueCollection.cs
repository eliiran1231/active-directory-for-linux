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
public class PropertyValueCollection : CollectionBase, IEnumerable<object>
{
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

    /// <summary>Gets the value at an index.</summary>
    public object this[int index]
    {
        get => List[index]!;
        set => List[index] = value;
    }

    /// <summary>
    /// The value in the shape Microsoft uses: null / single value / object[].
    /// Setting it replaces all current values.
    /// </summary>
    public object? Value
    {
        get => Count switch
        {
            0 => null,
            1 => List[0],
            _ => InnerList.ToArray(),
        };
        set
        {
            // Bypass CollectionBase's hooks so replacing the whole attribute
            // is recorded as one LDAP operation rather than Clear plus Adds.
            InnerList.Clear();
            if (value is byte[] bytes)
            {
                InnerList.Add(bytes);
            }
            else if (value is Array array)
            {
                // Match ADSI: every array except byte[] represents multiple
                // attribute values. Array.CopyTo boxes value-type elements.
                var many = new object[array.Length];
                array.CopyTo(many, 0);
                InnerList.AddRange(many);
            }
            else if (value is not null)
            {
                InnerList.Add(value);
            }

            RecordChange(
                Count == 0 ? PropertyValueChangeType.Clear : PropertyValueChangeType.Replace,
                InnerList.Cast<object>());
        }
    }

    /// <summary>Adds one value. Returns its index.</summary>
    public int Add(object value)
        => List.Add(value);

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
        AddRange(values.InnerList.Cast<object>().ToArray());
    }

    /// <summary>Removes one value.</summary>
    public void Remove(object value)
    {
        var index = List.IndexOf(value);
        if (index >= 0)
        {
            List.RemoveAt(index);
            return;
        }

        // ADSI still stages a single-value delete when a value is absent from
        // the local cache. Active Directory may have withheld it in a later
        // range of a large multi-valued attribute.
        RecordChange(PropertyValueChangeType.Delete, new[] { value });
    }

    /// <summary>Appends a value read from the server, without marking it changed.</summary>
    internal void AddLoaded(object value) => InnerList.Add(value);

    /// <summary>True if the value is present.</summary>
    public bool Contains(object value) => List.Contains(value);

    /// <summary>Copies the values to an array.</summary>
    public void CopyTo(object[] array, int index) => List.CopyTo(array, index);

    /// <summary>Returns the zero-based index of a value, or -1 when absent.</summary>
    public int IndexOf(object value) => List.IndexOf(value);

    /// <summary>Inserts a value at the specified index.</summary>
    public void Insert(int index, object value)
    {
        List.Insert(index, value);
    }

    protected override void OnInsertComplete(int index, object? value) =>
        RecordChange(PropertyValueChangeType.Add, new[] { value! });

    protected override void OnRemoveComplete(int index, object? value) =>
        RecordChange(PropertyValueChangeType.Delete, new[] { value! });

    protected override void OnSetComplete(int index, object? oldValue, object? newValue)
    {
        if (Count <= 1)
        {
            RecordChange(PropertyValueChangeType.Replace, InnerList.Cast<object>());
        }
        else
        {
            RecordChange(PropertyValueChangeType.Delete, new[] { oldValue! });
            RecordChange(PropertyValueChangeType.Add, new[] { newValue! });
        }
    }

    protected override void OnClearComplete() =>
        RecordChange(PropertyValueChangeType.Clear, Array.Empty<object>());

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

    public new IEnumerator<object> GetEnumerator() => InnerList.Cast<object>().GetEnumerator();
}

internal enum PropertyValueChangeType
{
    Add,
    Delete,
    Replace,
    Clear,
}

internal sealed record PropertyValueChange(PropertyValueChangeType Type, object[] Values);
