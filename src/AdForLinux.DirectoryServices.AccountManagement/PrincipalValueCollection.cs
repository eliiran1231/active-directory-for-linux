using System.Collections;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>A mutable, ordered collection of values belonging to a principal.</summary>
public class PrincipalValueCollection<T> : IList<T>, IList
{
    private readonly List<T> _values;
    private readonly Action<IReadOnlyList<T>>? _onChanged;
    private int _version;

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
            _version++;
            _ = _values[index];
            ThrowIfNull(value);
            _values[index] = value;
            Changed();
        }
    }

    public void Add(T value)
    {
        ThrowIfNull(value);
        _version++;
        _values.Add(value);
        Changed();
    }

    public void Clear()
    {
        _version++;
        _values.Clear();
        Changed();
    }

    public bool Contains(T value)
    {
        ThrowIfNull(value);
        return IndexOf(value) >= 0;
    }

    public int IndexOf(T value)
    {
        ThrowIfNull(value);
        // Microsoft dispatches through object.Equals, even when T implements
        // IEquatable<T> with different equality semantics.
        for (var index = 0; index < _values.Count; index++)
        {
            if (object.Equals(_values[index], value)) return index;
        }

        return -1;
    }

    public void Insert(int index, T value)
    {
        _version++;
        ThrowIfNull(value);
        _values.Insert(index, value);
        Changed();
    }

    public bool Remove(T value)
    {
        ThrowIfNull(value);
        _version++;
        var index = IndexOf(value);
        if (index >= 0)
        {
            _values.RemoveAt(index);
            Changed();
        }

        return index >= 0;
    }

    public void RemoveAt(int index)
    {
        _version++;
        _values.RemoveAt(index);
        Changed();
    }

    public void CopyTo(T[] array, int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ValidateCopyBoundary(array, index);
        _values.CopyTo(array, index);
    }

    public IEnumerator<T> GetEnumerator() => new Enumerator(this);
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    // Mutation attempts invalidate traversal even when no value is removed or
    // index validation fails. Add/Remove reject null before invalidating it.
    // Current also validates position and disposal.
    private sealed class Enumerator : IEnumerator<T>
    {
        private readonly PrincipalValueCollection<T> _owner;
        private readonly int _version;
        private readonly IEnumerator<T> _inner;
        private T _current = default!;
        private bool _hasCurrent;
        private bool _disposed;

        internal Enumerator(PrincipalValueCollection<T> owner)
        {
            _owner = owner;
            _version = owner._version;
            _inner = owner._values.GetEnumerator();
        }

        public T Current
        {
            get
            {
                CheckDisposed();
                if (!_hasCurrent)
                {
                    throw new InvalidOperationException("Enumeration has either not started or has already finished.");
                }

                // Current remains cached even if the collection changes size.
                return _current;
            }
        }

        object? IEnumerator.Current => Current;

        public bool MoveNext()
        {
            CheckDisposed();
            CheckVersion();
            _hasCurrent = _inner.MoveNext();
            _current = _hasCurrent ? _inner.Current : default!;
            return _hasCurrent;
        }

        public void Reset()
        {
            CheckDisposed();
            CheckVersion();
            _inner.Reset();
            _hasCurrent = false;
            _current = default!;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _inner.Dispose();
            _disposed = true;
        }

        private void CheckDisposed()
        {
            if (_disposed) throw new ObjectDisposedException("ValueCollectionEnumerator");
        }

        private void CheckVersion()
        {
            if (_version != _owner._version)
            {
                throw new InvalidOperationException("Collection was modified; enumeration operation may not execute.");
            }
        }
    }

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
        // Microsoft returns the new count, unlike the usual IList convention.
        return Count;
    }

    bool IList.Contains(object? value) => Contains(Cast(value));
    int IList.IndexOf(object? value) => IndexOf(Cast(value));
    void IList.Insert(int index, object? value) => Insert(index, Cast(value));
    void IList.Remove(object? value) => Remove(Cast(value));
    void ICollection.CopyTo(Array array, int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ValidateCopyBoundary(array, index);
        ArgumentNullException.ThrowIfNull(array);
        if (array.Rank != 1)
        {
            throw new ArgumentException("The destination array must have one dimension.");
        }

        // Validate element compatibility only as each value is copied, including
        // partial writes on failure and no type check for an empty collection.
        foreach (var value in _values)
        {
            array.SetValue(value, index++);
        }
    }

    private void ValidateCopyBoundary(Array array, int index)
    {
        // Even an empty collection requires a position inside the target array.
        // Validate capacity here so both CopyTo paths omit the parameter name.
        if (array is not null && (index >= array.Length || Count > array.Length - index))
        {
            throw new ArgumentException("The destination array has insufficient space at the specified index.");
        }
    }

    private static T Cast(object? value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return (T)value;
    }
}
