using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Schema class names used by <see cref="DirectoryEntries.SchemaFilter"/>.
/// </summary>
public class SchemaNameCollection : IList
{
    // Structural changes replace the array, while indexer writes update it in
    // place. Existing enumerators therefore retain their original array.
    private string?[] _names = Array.Empty<string?>();

    internal SchemaNameCollection()
    {
    }

    public int Count => _names.Length;

    public string? this[int index]
    {
        get
        {
            ValidateIndex(index);
            return _names[index];
        }
        set
        {
            ValidateIndex(index);
            _names[index] = value;
        }
    }

    public int Add(string? value)
    {
        var index = Count;
        Insert(index, value);
        return index;
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

    public void Clear() => _names = Array.Empty<string?>();

    public bool Contains(string? value) => IndexOf(value) >= 0;

    public void CopyTo(string?[] stringArray, int index) => _names.CopyTo(stringArray, index);

    public int IndexOf(string? value) => Array.IndexOf(_names, value);

    public void Insert(int index, string? value)
    {
        if ((uint)index > (uint)Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        var names = new string?[Count + 1];
        Array.Copy(_names, 0, names, 0, index);
        names[index] = value;
        Array.Copy(_names, index, names, index + 1, Count - index);
        _names = names;
    }

    public void Remove(string? value)
    {
        var index = IndexOf(value);
        RemoveAt(index);
    }

    public void RemoveAt(int index)
    {
        if ((uint)index >= (uint)Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        var names = new string?[Count - 1];
        Array.Copy(_names, 0, names, 0, index);
        Array.Copy(_names, index + 1, names, index, Count - index - 1);
        _names = names;
    }

    // Microsoft enumerates the captured schema array across later mutations.
    public IEnumerator GetEnumerator() => _names.GetEnumerator();

    private void ValidateIndex(int index)
    {
        if ((uint)index >= (uint)_names.Length)
        {
            throw new IndexOutOfRangeException();
        }
    }

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
