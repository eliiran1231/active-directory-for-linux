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

    /// <summary>
    /// Removes one managed property-cache entry. Existing callers that hold the
    /// removed value collection keep that snapshot, while the next lookup gets
    /// a newly loaded collection, matching DirectoryEntry's partial-refresh
    /// behavior.
    /// </summary>
    internal void RemoveCached(string propertyName) => _byName.Remove(propertyName);

    /// <summary>Replaces one managed property-cache entry with server values.</summary>
    internal void ReplaceLoaded(string propertyName, IEnumerable<object> values)
    {
        var replacement = new PropertyValueCollection(propertyName, _onChanged);
        foreach (var value in values)
        {
            replacement.AddLoaded(value);
        }

        _byName[propertyName] = replacement;
    }

    public IDictionaryEnumerator GetEnumerator() => new PropertyEnumerator(_byName.GetEnumerator());

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<PropertyValueCollection> IEnumerable<PropertyValueCollection>.GetEnumerator() =>
        _byName.Values.GetEnumerator();

    bool IDictionary.IsFixedSize => true;

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

    void ICollection.CopyTo(Array array, int index)
    {
        ArgumentNullException.ThrowIfNull(array);
        if (array.Rank != 1)
        {
            throw new ArgumentException("Only single-dimensional arrays are supported.", nameof(array));
        }

        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        if (index > array.Length - Count)
        {
            throw new ArgumentException("The destination array is not large enough.", nameof(array));
        }

        foreach (var value in _byName.Values)
        {
            array.SetValue(value, index++);
        }
    }

    private sealed class PropertyEnumerator : IDictionaryEnumerator, IDisposable
    {
        private readonly IEnumerator<KeyValuePair<string, PropertyValueCollection>> _inner;

        internal PropertyEnumerator(IEnumerator<KeyValuePair<string, PropertyValueCollection>> inner)
        {
            _inner = inner;
        }

        public object Current => Value;

        public DictionaryEntry Entry => new(Key, Value);

        public object Key => _inner.Current.Key;

        public object Value => _inner.Current.Value;

        public bool MoveNext() => _inner.MoveNext();

        public void Reset() => _inner.Reset();

        public void Dispose() => _inner.Dispose();
    }
}
