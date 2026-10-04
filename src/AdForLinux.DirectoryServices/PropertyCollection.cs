using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// All loaded attributes of a <see cref="DirectoryEntry"/>, keyed by name.
/// Like Microsoft's type, asking for a missing attribute returns an empty
/// collection (it does not throw), so callers can always read <c>.Value</c>.
/// </summary>
public class PropertyCollection : IDictionary, IEnumerable<PropertyValueCollection>
{
    private readonly Dictionary<string, PropertyValueCollection> _byName =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PropertyValueCollection> _cachedValues =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Action<PropertyValueCollection>? _onChanged;

    internal PropertyCollection(Action<PropertyValueCollection>? onChanged = null, Action? validateOwner = null)
    {
        _onChanged = onChanged;
        _validateOwner = validateOwner;
    }

    private Func<PropertyCollection>? _load;
    private readonly Action? _validateOwner;

    internal PropertyCollection(Action<PropertyValueCollection> onChanged, Func<PropertyCollection> load, Action? validateOwner = null)
        : this(onChanged)
    {
        _load = load;
        _validateOwner = validateOwner;
    }

    // A successful partial refresh establishes the cache without fetching all
    // attributes through a previously created, still-unloaded wrapper.
    internal void MarkLoaded() => _load = null;

    internal void EnsureLoaded()
    {
        if (_load is null) return;
        // Keep the loader on failure so the same wrapper can retry binding.
        var loaded = _load();
        foreach (var property in loaded._byName.Values)
            ReplaceLoaded(property.PropertyName, property.Select(value => value!));
        _load = null;
    }

    /// <summary>
    /// The values for one attribute. Creates an empty collection on first use
    /// of an unknown name, matching Microsoft, so writes can start from nothing.
    /// </summary>
    public PropertyValueCollection this[string propertyName]
    {
        get
        {
            ArgumentNullException.ThrowIfNull(propertyName);
            EnsureLoaded();
            if (!_cachedValues.TryGetValue(propertyName, out var values))
            {
                values = new PropertyValueCollection(propertyName, OnChanged, _validateOwner);
                _cachedValues[propertyName] = values;
            }

            return values;
        }
    }

    /// <summary>True if the attribute has been loaded and exists.</summary>
    public bool Contains(string propertyName)
    {
        _validateOwner?.Invoke();
        ArgumentNullException.ThrowIfNull(propertyName);
        EnsureLoaded();
        return _byName.ContainsKey(propertyName);
    }

    /// <summary>Number of distinct attributes.</summary>
    public int Count { get { EnsureLoaded(); return _byName.Count; } }

    /// <summary>All attribute names.</summary>
    public ICollection PropertyNames => new PropertyView(this, names: true);

    /// <summary>All property value collections.</summary>
    public ICollection Values => new PropertyView(this, names: false);

    /// <summary>Copies the property value collections to an array.</summary>
    public void CopyTo(PropertyValueCollection[] array, int index) =>
        ((ICollection)this).CopyTo(array, index);

    internal PropertyValueCollection GetOrAdd(string propertyName)
    {
        var values = this[propertyName];
        _byName[propertyName] = values;
        return values;
    }

    private void OnChanged(PropertyValueCollection values)
    {
        // A read only caches a wrapper. A write makes it a property, but an
        // old wrapper retained across refresh must not replace the fresh one.
        if (_cachedValues.TryGetValue(values.PropertyName, out var current)
            && ReferenceEquals(current, values))
        {
            _byName[values.PropertyName] = values;
        }

        _onChanged?.Invoke(values);
    }

    /// <summary>
    /// Removes one managed property-cache entry. Existing callers that hold the
    /// removed value collection keep that snapshot, while the next lookup gets
    /// a newly loaded collection, matching DirectoryEntry's partial-refresh
    /// behavior.
    /// </summary>
    internal void RemoveCached(string propertyName)
    {
        _byName.Remove(propertyName);
        _cachedValues.Remove(propertyName);
    }

    /// <summary>Replaces one managed property-cache entry with server values.</summary>
    internal void ReplaceLoaded(string propertyName, IEnumerable<object> values)
    {
        var replacement = new PropertyValueCollection(propertyName, OnChanged, _validateOwner);
        foreach (var value in values)
        {
            replacement.AddLoaded(value);
        }

        _byName[propertyName] = replacement;
        _cachedValues[propertyName] = replacement;
    }

    public IDictionaryEnumerator GetEnumerator()
    {
        EnsureLoaded();
        // Pending writes must not invalidate an already-created enumerator.
        // Values are copied too, keeping each returned wrapper independent.
        return new PropertyEnumerator(_byName.Values.ToArray(), _onChanged, _validateOwner);
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<PropertyValueCollection> IEnumerable<PropertyValueCollection>.GetEnumerator()
    {
        EnsureLoaded();
        return _byName.Values.GetEnumerator();
    }

    bool IDictionary.IsFixedSize => true;

    bool IDictionary.IsReadOnly => true;

    ICollection IDictionary.Keys => PropertyNames;

    object? IDictionary.this[object key]
    {
        get => this[(string)key];
        set => throw new NotSupportedException("The property dictionary is read-only.");
    }

    void IDictionary.Add(object key, object? value) =>
        throw new NotSupportedException("The property dictionary is read-only.");

    void IDictionary.Clear() => throw new NotSupportedException("The property dictionary is read-only.");

    bool IDictionary.Contains(object key) => Contains((string)key);

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
            // Microsoft passes its lower-bound message as the parameter name.
            throw new ArgumentOutOfRangeException("Number was less than the array's lower bound in the first dimension.", nameof(index));
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

    private sealed class PropertyView(PropertyCollection owner, bool names) : ICollection
    {
        private ICollection Items
        {
            get
            {
                owner.EnsureLoaded();
                return names ? owner._byName.Keys : owner._byName.Values;
            }
        }

        public int Count => owner.Count;
        public bool IsSynchronized => false;
        public object SyncRoot => owner;
        public void CopyTo(Array array, int index) => Items.CopyTo(array, index);
        public IEnumerator GetEnumerator() => Items.GetEnumerator();
    }

    private sealed class PropertyEnumerator : IDictionaryEnumerator, IDisposable
    {
        private readonly (string Name, object[] Values)[] _snapshot;
        private readonly Action<PropertyValueCollection>? _onChanged;
        private readonly Action? _validateOwner;
        private int _index = -1;

        internal PropertyEnumerator(PropertyValueCollection[] properties, Action<PropertyValueCollection>? onChanged, Action? validateOwner)
        {
            _snapshot = properties.Select(property =>
                (property.PropertyName, property.Select(value => value!).ToArray())).ToArray();
            _onChanged = onChanged;
            _validateOwner = validateOwner;
        }

        private void ValidatePosition()
        {
            if (_index < 0 || _index >= _snapshot.Length)
                throw new InvalidOperationException("Enumeration has either not started or has already finished.");
        }

        public object Current => Value;
        public DictionaryEntry Entry => new(Key, Value);
        public object Key { get { ValidatePosition(); return _snapshot[_index].Name; } }
        public object Value
        {
            get
            {
                ValidatePosition();
                var property = _snapshot[_index];
                var values = new PropertyValueCollection(property.Name, _onChanged, _validateOwner);
                foreach (var value in property.Values) values.AddLoaded(value);
                return values;
            }
        }

        public bool MoveNext()
        {
            if (_index < _snapshot.Length) _index++;
            return _index < _snapshot.Length;
        }
        public void Reset() => _index = -1;
        public void Dispose() { }
    }
}
