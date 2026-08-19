using System.Collections;
using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The results of <see cref="DirectorySearcher.FindAll"/>, like Microsoft's
/// <c>SearchResultCollection</c>.
/// </summary>
public sealed class SearchResultCollection : MarshalByRefObject, IReadOnlyList<SearchResult>, ICollection, IDisposable
{
    private IReadOnlyList<SearchResult>? _results;
    private readonly IEnumerable<SearchResult>? _streamingResults;
    private readonly ReplayableSearchResults? _replayableResults;
    private readonly ForwardOnlySearchResults? _forwardOnlyResults;
    private bool _disposed;

    internal SearchResultCollection(IReadOnlyList<SearchResult> results, string[]? propertiesLoaded = null)
    {
        _results = results;
        PropertiesLoaded = propertiesLoaded?.ToArray() ?? Array.Empty<string>();
    }

    internal SearchResultCollection(
        IEnumerable<SearchResult> results,
        bool cacheResults,
        string[]? propertiesLoaded = null)
    {
        _streamingResults = results;
        _replayableResults = cacheResults ? new ReplayableSearchResults(results) : null;
        _forwardOnlyResults = cacheResults ? null : new ForwardOnlySearchResults(results);
        PropertiesLoaded = propertiesLoaded?.ToArray() ?? Array.Empty<string>();
    }

    public SearchResult this[int index] => Materialize()[index];

    public int Count => Materialize().Count;

    /// <summary>
    /// Gets the native ADSI search handle.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The collection has been disposed.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Protocol-based searches do not expose ADSI's native search handle.
    /// </exception>
    public IntPtr Handle
    {
        get
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SearchResultCollection));
            }

            throw new PlatformNotSupportedException(
                "SearchResultCollection.Handle exposes an ADSI native search handle, which is not available for protocol-based searches.");
        }
    }

    /// <summary>The attributes explicitly requested from the searcher.</summary>
    public string[] PropertiesLoaded { get; }

    public bool Contains(SearchResult result) => Materialize().Contains(result);

    public void CopyTo(SearchResult[] results, int index)
    {
        ArgumentNullException.ThrowIfNull(results);
        var materialized = Materialize();
        for (var i = 0; i < materialized.Count; i++)
        {
            results[index + i] = materialized[i];
        }
    }

    public int IndexOf(SearchResult result)
    {
        var materialized = Materialize();
        for (var i = 0; i < materialized.Count; i++)
        {
            if (ReferenceEquals(materialized[i], result))
            {
                return i;
            }
        }

        return -1;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        (_streamingResults as IDisposable)?.Dispose();
        _forwardOnlyResults?.Dispose();
        _disposed = true;
    }

    public IEnumerator GetEnumerator() => GetGenericEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<SearchResult> IEnumerable<SearchResult>.GetEnumerator() => GetGenericEnumerator();

    private IEnumerator<SearchResult> GetGenericEnumerator()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_results is not null)
        {
            return _results.GetEnumerator();
        }

        if (_replayableResults is not null)
        {
            return _replayableResults.GetEnumerator();
        }

        return _forwardOnlyResults!.ClaimEnumerator();
    }

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index)
    {
        var materialized = Materialize();
        for (var i = 0; i < materialized.Count; i++)
        {
            array.SetValue(materialized[i], index + i);
        }
    }

    private IReadOnlyList<SearchResult> Materialize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_results is not null)
        {
            return _results;
        }

        if (_replayableResults is not null)
        {
            return _results = _replayableResults.Materialize();
        }

        return _results = _forwardOnlyResults!.MaterializeRemaining();
    }

    private sealed class ForwardOnlySearchResults : IDisposable
    {
        private readonly object _gate = new();
        private readonly IEnumerator<SearchResult> _source;
        private IReadOnlyList<SearchResult>? _materializedRemaining;
        private bool _claimed;
        private bool _complete;

        internal ForwardOnlySearchResults(IEnumerable<SearchResult> source) =>
            _source = source.GetEnumerator();

        internal IEnumerator<SearchResult> ClaimEnumerator()
        {
            lock (_gate)
            {
                if (_claimed)
                {
                    return Enumerable.Empty<SearchResult>().GetEnumerator();
                }

                _claimed = true;
                return new Enumerator(this);
            }
        }

        internal IReadOnlyList<SearchResult> MaterializeRemaining()
        {
            lock (_gate)
            {
                if (_materializedRemaining is not null)
                {
                    return _materializedRemaining;
                }

                var remaining = new List<SearchResult>();
                try
                {
                    while (!_complete && _source.MoveNext())
                    {
                        remaining.Add(_source.Current);
                    }

                    Complete();
                    return _materializedRemaining = remaining;
                }
                catch
                {
                    Complete();
                    throw;
                }
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                Complete();
            }
        }

        private bool TryMoveNext(out SearchResult result)
        {
            lock (_gate)
            {
                if (_complete)
                {
                    result = null!;
                    return false;
                }

                try
                {
                    if (_source.MoveNext())
                    {
                        result = _source.Current;
                        return true;
                    }

                    Complete();
                    result = null!;
                    return false;
                }
                catch
                {
                    Complete();
                    throw;
                }
            }
        }

        private void Complete()
        {
            if (_complete)
            {
                return;
            }

            _complete = true;
            _source.Dispose();
        }

        private sealed class Enumerator(ForwardOnlySearchResults owner) : IEnumerator<SearchResult>
        {
            private SearchResult? _current;

            public SearchResult Current => _current!;

            object IEnumerator.Current => Current;

            public bool MoveNext() => owner.TryMoveNext(out _current!);

            public void Reset() => throw new NotSupportedException();

            public void Dispose()
            {
                // The collection owns the shared cursor. Disposing a claimed
                // enumerator must not discard results that can still be
                // materialized by collection operations.
            }
        }
    }

    private sealed class ReplayableSearchResults : IEnumerable<SearchResult>
    {
        private readonly object _gate = new();
        private readonly IEnumerator<SearchResult> _source;
        private readonly List<SearchResult> _cache = new();
        private bool _complete;

        internal ReplayableSearchResults(IEnumerable<SearchResult> source) =>
            _source = source.GetEnumerator();

        public IEnumerator<SearchResult> GetEnumerator()
        {
            var index = 0;
            while (TryGet(index++, out var result))
            {
                yield return result;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        internal IReadOnlyList<SearchResult> Materialize()
        {
            while (TryGet(_cache.Count, out _))
            {
            }

            return _cache;
        }

        private bool TryGet(int index, out SearchResult result)
        {
            lock (_gate)
            {
                if (index < _cache.Count)
                {
                    result = _cache[index];
                    return true;
                }

                if (_complete || !_source.MoveNext())
                {
                    _complete = true;
                    _source.Dispose();
                    result = null!;
                    return false;
                }

                result = _source.Current;
                _cache.Add(result);
                return true;
            }
        }
    }
}

internal sealed class StreamingSearchResultSource : IEnumerable<SearchResult>, IDisposable
{
    private readonly BlockingCollection<SearchResult> _results = new();
    private readonly CancellationTokenSource _cancellation = new();
    private readonly Task _producer;
    private ExceptionDispatchInfo? _error;

    internal StreamingSearchResultSource(Action<Action<SearchResult>, CancellationToken> produce)
    {
        _producer = Task.Run(() =>
        {
            try
            {
                produce(result => _results.Add(result, _cancellation.Token), _cancellation.Token);
            }
            catch (OperationCanceledException) when (_cancellation.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _error = ExceptionDispatchInfo.Capture(ex);
            }
            finally
            {
                _results.CompleteAdding();
            }
        });
    }

    public IEnumerator<SearchResult> GetEnumerator()
    {
        foreach (var result in _results.GetConsumingEnumerable())
        {
            yield return result;
        }

        _error?.Throw();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public void Dispose()
    {
        _cancellation.Cancel();
        _ = _producer;
    }
}
