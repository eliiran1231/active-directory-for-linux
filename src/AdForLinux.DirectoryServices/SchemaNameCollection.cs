using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Schema class names used by <see cref="DirectoryEntries.SchemaFilter"/>.
/// </summary>
public class SchemaNameCollection : IList
{
    private readonly List<string?> _names = new();

    internal SchemaNameCollection()
    {
    }

    public int Count => _names.Count;

    public string? this[int index]
    {
        get => _names[index];
        set => _names[index] = value;
    }

    public int Add(string? value)
    {
        _names.Add(value);
        return _names.Count - 1;
    }

    public void AddRange(string?[] value)
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

    public bool Contains(string? value) => IndexOf(value) >= 0;

    public void CopyTo(string?[] stringArray, int index) => _names.CopyTo(stringArray, index);

    public int IndexOf(string? value) => _names.IndexOf(value);

    public void Insert(int index, string? value)
    {
        _names.Insert(index, value);
    }

    public void Remove(string? value)
    {
        var index = IndexOf(value);
        RemoveAt(index);
    }

    public void RemoveAt(int index) => _names.RemoveAt(index);

    public IEnumerator GetEnumerator() => _names.GetEnumerator();

    bool IList.IsFixedSize => false;

    bool IList.IsReadOnly => false;

    object? IList.this[int index]
    {
        get => this[index];
        set => this[index] = (string?)value;
    }

    int IList.Add(object? value) => Add((string?)value);

    bool IList.Contains(object? value) => Contains((string?)value);

    int IList.IndexOf(object? value) => IndexOf((string?)value);

    void IList.Insert(int index, object? value) => Insert(index, (string?)value);

    void IList.Remove(object? value) => Remove((string?)value);

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index) => ((ICollection)_names).CopyTo(array, index);
}
