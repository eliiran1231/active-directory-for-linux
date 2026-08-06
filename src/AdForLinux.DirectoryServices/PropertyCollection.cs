using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// All loaded attributes of a <see cref="DirectoryEntry"/>, keyed by name.
/// Like Microsoft's type, asking for a missing attribute returns an empty
/// collection (it does not throw), so callers can always read <c>.Value</c>.
/// </summary>
public sealed class PropertyCollection : IEnumerable<PropertyValueCollection>
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
    public ICollection<string> PropertyNames => _byName.Keys;

    internal PropertyValueCollection GetOrAdd(string propertyName) => this[propertyName];

    public IEnumerator<PropertyValueCollection> GetEnumerator() => _byName.Values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
