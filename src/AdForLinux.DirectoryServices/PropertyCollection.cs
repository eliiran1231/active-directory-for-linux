using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// All loaded attributes of a <see cref="DirectoryEntry"/>, keyed by name.
/// Like Microsoft's type, asking for a missing attribute returns an empty
/// collection (it does not throw), so callers can always read <c>.Value</c>.
/// </summary>
public sealed class PropertyCollection : IDictionary, IEnumerable<PropertyValueCollection>
{
    private readonly Dictionary<string, PropertyValueCollection> _byName =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Action<PropertyValueCollection>? _onChanged;

    internal PropertyCollection(Action<PropertyValueCollection>? onChanged = null)
    {
        _onChanged = onChanged;
    }

    /// <summary>
    /// The values for one attribute. Creates an empty collection on first use
    /// of an unknown name, matching Microsoft, so writes can start from nothing.
    /// </summary>
    public PropertyValueCollection this[string propertyName]
    {
        get
        {
            if (!_byName.TryGetValue(propertyName, out var values))
            {
                values = new PropertyValueCollection(propertyName, _onChanged);
                _byName[propertyName] = values;
            }

            return values;
        }
    }

    /// <summary>True if the attribute has been loaded and exists.</summary>
    public bool Contains(string propertyName) => _byName.ContainsKey(propertyName);

    /// <summary>Number of distinct attributes.</summary>
    public int Count => _byName.Count;

    /// <summary>All attribute names.</summary>
    public ICollection PropertyNames => _byName.Keys;

    /// <summary>All property value collections.</summary>
    public ICollection Values => _byName.Values;

    /// <summary>Copies the property value collections to an array.</summary>
    public void CopyTo(PropertyValueCollection[] array, int index) =>
        _byName.Values.CopyTo(array, index);

    internal PropertyValueCollection GetOrAdd(string propertyName) => this[propertyName];

    public IDictionaryEnumerator GetEnumerator() => ((IDictionary)_byName).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<PropertyValueCollection> IEnumerable<PropertyValueCollection>.GetEnumerator() =>
        _byName.Values.GetEnumerator();

    bool IDictionary.IsFixedSize => false;

    bool IDictionary.IsReadOnly => true;

    ICollection IDictionary.Keys => PropertyNames;

    ICollection IDictionary.Values => Values;

    object? IDictionary.this[object key]
    {
        get => key is string name ? this[name] : null;
        set => throw new NotSupportedException("The property dictionary is read-only.");
    }

    void IDictionary.Add(object key, object? value) =>
        throw new NotSupportedException("The property dictionary is read-only.");

    void IDictionary.Clear() => throw new NotSupportedException("The property dictionary is read-only.");

    bool IDictionary.Contains(object key) => key is string name && Contains(name);

    IDictionaryEnumerator IDictionary.GetEnumerator() => GetEnumerator();

    void IDictionary.Remove(object key) =>
        throw new NotSupportedException("The property dictionary is read-only.");

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index) => ((ICollection)_byName).CopyTo(array, index);
}
