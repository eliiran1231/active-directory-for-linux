using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Schema class names used by <see cref="DirectoryEntries.SchemaFilter"/>.
/// </summary>
public sealed class SchemaNameCollection : IList, IEnumerable<string>
{
    private readonly List<string> _names = new();

    internal SchemaNameCollection()
    {
    }

    public int Count => _names.Count;

    public string this[int index]
    {
        get => _names[index];
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _names[index] = value;
        }
    }

    public int Add(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _names.Add(value);
        return _names.Count - 1;
    }

    public void AddRange(string[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        foreach (var name in value)
        {
            Add(name);
        }
    }

    public void AddRange(SchemaNameCollection value)
    {
        ArgumentNullException.ThrowIfNull(value);
        AddRange(value._names.ToArray());
    }

    public void Clear() => _names.Clear();

    public bool Contains(string value) => IndexOf(value) >= 0;

    public void CopyTo(string[] array, int index) => _names.CopyTo(array, index);

    public int IndexOf(string value) =>
        _names.FindIndex(name => string.Equals(name, value, StringComparison.OrdinalIgnoreCase));

    public void Insert(int index, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _names.Insert(index, value);
    }

    public void Remove(string value)
    {
        var index = IndexOf(value);
        if (index >= 0)
        {
            _names.RemoveAt(index);
        }
    }

    public void RemoveAt(int index) => _names.RemoveAt(index);

    public IEnumerator<string> GetEnumerator() => _names.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    bool IList.IsFixedSize => false;

    bool IList.IsReadOnly => false;

    object? IList.this[int index]
    {
        get => this[index];
        set => this[index] = RequireString(value);
    }

    int IList.Add(object? value) => Add(RequireString(value));

    bool IList.Contains(object? value) => value is string name && Contains(name);

    int IList.IndexOf(object? value) => value is string name ? IndexOf(name) : -1;

    void IList.Insert(int index, object? value) => Insert(index, RequireString(value));

    void IList.Remove(object? value)
    {
        if (value is string name)
        {
            Remove(name);
        }
    }

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index) => ((ICollection)_names).CopyTo(array, index);

    private static string RequireString(object? value) =>
        value as string ?? throw new ArgumentException("Schema names must be strings.", nameof(value));
}
