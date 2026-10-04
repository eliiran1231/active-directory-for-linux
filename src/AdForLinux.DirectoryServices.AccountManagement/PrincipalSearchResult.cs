using System.Collections;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The results of a principal search, like Microsoft's
/// <c>PrincipalSearchResult&lt;T&gt;</c>. Enumerate it to read the matches.
/// </summary>
public class PrincipalSearchResult<T> : IEnumerable<T>, IDisposable
{
    private readonly IReadOnlyList<T> _results;
    private readonly Func<int, T>? _project;
    private readonly int _count;
    private int _position = -1;
    private bool _disposed;

    internal PrincipalSearchResult(IReadOnlyList<T> results)
    {
        _results = results;
        _count = results.Count;
    }

    internal PrincipalSearchResult(int count, Func<int, T> project)
    {
        _results = Array.Empty<T>();
        _count = count;
        _project = project;
    }

    public IEnumerator<T> GetEnumerator()
    {
        ThrowIfDisposed();
        return new FindResultEnumerator(this);
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException("PrincipalSearchResult");
        }
    }

    private sealed class FindResultEnumerator : IEnumerator<T>
    {
        private readonly PrincipalSearchResult<T> _owner;
        private bool _disposed;
        private bool _hasCurrent;
        private bool _started;
        private bool _endReached;

        internal FindResultEnumerator(PrincipalSearchResult<T> owner)
        {
            _owner = owner;
        }

        public T Current
        {
            get
            {
                CheckDisposed();
                if (!_hasCurrent)
                {
                    throw new InvalidOperationException("Enumeration has not started or has already finished.");
                }
                return _owner._project is not null
                    ? _owner._project(_owner._position)
                    : _owner._results[_owner._position];
            }
        }

        object IEnumerator.Current => Current!;

        public bool MoveNext()
        {
            CheckDisposed();
            if (_endReached)
            {
                return false;
            }

            _hasCurrent = false;
            // Microsoft shares the row position, but keeps start/end flags per
            // enumerator. Rewind only when a new or reset cursor first moves.
            if (!_started)
            {
                _owner._position = -1;
                _started = true;
            }
            _hasCurrent = ++_owner._position < _owner._count;
            _endReached = !_hasCurrent;
            return _hasCurrent;
        }

        public void Reset()
        {
            CheckDisposed();
            _started = false;
            _hasCurrent = false;
            _endReached = false;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        private void CheckDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("FindResultEnumerator");
            }
        }
    }
}
