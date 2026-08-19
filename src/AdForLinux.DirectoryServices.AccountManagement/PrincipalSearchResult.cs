using System.Collections;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The results of a principal search, like Microsoft's
/// <c>PrincipalSearchResult&lt;T&gt;</c>. Enumerate it to read the matches.
/// </summary>
public class PrincipalSearchResult<T> : IEnumerable<T>, IDisposable
    where T : Principal
{
    private readonly IReadOnlyList<T> _results;
    private bool _disposed;

    internal PrincipalSearchResult(IReadOnlyList<T> results)
    {
        _results = results;
    }

    public IEnumerator<T> GetEnumerator()
    {
        ThrowIfDisposed();
        return new FindResultEnumerator<T>(_results.GetEnumerator());
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

    private sealed class FindResultEnumerator<TPrincipal> : IEnumerator<TPrincipal>
    {
        private readonly IEnumerator<TPrincipal> _inner;
        private bool _disposed;

        internal FindResultEnumerator(IEnumerator<TPrincipal> inner)
        {
            _inner = inner;
        }

        public TPrincipal Current
        {
            get
            {
                CheckDisposed();
                return _inner.Current;
            }
        }

        object IEnumerator.Current => Current!;

        public bool MoveNext()
        {
            CheckDisposed();
            return _inner.MoveNext();
        }

        public void Reset()
        {
            CheckDisposed();
            _inner.Reset();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _inner.Dispose();
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
