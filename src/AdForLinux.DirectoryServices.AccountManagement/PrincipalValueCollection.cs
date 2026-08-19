using System.Collections;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>A mutable, ordered collection of values belonging to a principal.</summary>
public class PrincipalValueCollection<T> : IList<T>, IList
{
    private readonly List<T> _values;
    private readonly Action<IReadOnlyList<T>>? _onChanged;

    internal PrincipalValueCollection()
        : this(Array.Empty<T>(), null)
    {
    }

    internal PrincipalValueCollection(IEnumerable<T> values, Action<IReadOnlyList<T>>? onChanged)
    {
        _values = new List<T>(values);
        _onChanged = onChanged;
    }

    public int Count => _values.Count;
    public bool IsFixedSize => false;
    public bool IsReadOnly => false;
    public bool IsSynchronized => false;
    public object SyncRoot => this;

    bool ICollection.IsSynchronized => IsSynchronized;

    object ICollection.SyncRoot => SyncRoot;

    public T this[int index]
    {
        get => _values[index];
        set
        {
            ThrowIfNull(value);
            _values[index] = value;
            Changed();
        }
    }

    public void Add(T value)
    {
        ThrowIfNull(value);
        _values.Add(value);
        Changed();
    }

    public void Clear()
    {
        _values.Clear();
        Changed();
    }

    public bool Contains(T value)
    {
        ThrowIfNull(value);
        return _values.Contains(value);
    }

    public int IndexOf(T value)
    {
        ThrowIfNull(value);
        return _values.IndexOf(value);
    }

    public void Insert(int index, T value)
    {
        ThrowIfNull(value);
        _values.Insert(index, value);
        Changed();
    }

    public bool Remove(T value)
    {
        ThrowIfNull(value);
        var removed = _values.Remove(value);
        if (removed)
        {
            Changed();
        }

        return removed;
    }

    public void RemoveAt(int index)
    {
        _values.RemoveAt(index);
        Changed();
    }

    public void CopyTo(T[] array, int index) => _values.CopyTo(array, index);
    public IEnumerator<T> GetEnumerator() => _values.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    private void Changed() => _onChanged?.Invoke(_values);

    private static void ThrowIfNull(T value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }
    }

    bool IList.IsFixedSize => IsFixedSize;
    bool IList.IsReadOnly => IsReadOnly;
    object? IList.this[int index]
    {
        get => this[index];
        set => this[index] = Cast(value);
    }

    int IList.Add(object? value)
    {
        Add(Cast(value));
        return Count - 1;
    }

    bool IList.Contains(object? value) => Contains(Cast(value));
    int IList.IndexOf(object? value) => IndexOf(Cast(value));
    void IList.Insert(int index, object? value) => Insert(index, Cast(value));
    void IList.Remove(object? value) => Remove(Cast(value));
    void ICollection.CopyTo(Array array, int index) => ((ICollection)_values).CopyTo(array, index);

    private static T Cast(object? value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return (T)value;
    }
}
