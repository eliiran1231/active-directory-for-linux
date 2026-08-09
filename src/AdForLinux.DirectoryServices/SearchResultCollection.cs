using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The results of <see cref="DirectorySearcher.FindAll"/>, like Microsoft's
/// <c>SearchResultCollection</c>.
/// </summary>
public sealed class SearchResultCollection : MarshalByRefObject, IReadOnlyList<SearchResult>, ICollection, IDisposable
{
    private readonly IReadOnlyList<SearchResult> _results;
    private bool _disposed;

    internal SearchResultCollection(IReadOnlyList<SearchResult> results, string[]? propertiesLoaded = null)
    {
        _results = results;
        PropertiesLoaded = propertiesLoaded?.ToArray() ?? Array.Empty<string>();
    }

    public SearchResult this[int index] => _results[index];

    public int Count => _results.Count;

    /// <summary>
    /// The native ADSI search handle. Protocol-based searches do not expose a
    /// native handle, so this is <see cref="IntPtr.Zero"/> while undisposed.
    /// </summary>
    public IntPtr Handle => _disposed
        ? throw new ObjectDisposedException(nameof(SearchResultCollection))
        : IntPtr.Zero;

    /// <summary>The attributes explicitly requested from the searcher.</summary>
    public string[] PropertiesLoaded { get; }

    public bool Contains(SearchResult result) => _results.Contains(result);

    public void CopyTo(SearchResult[] results, int index)
    {
        ArgumentNullException.ThrowIfNull(results);
        for (var i = 0; i < _results.Count; i++)
        {
            results[index + i] = _results[i];
        }
    }

    public int IndexOf(SearchResult result)
    {
        for (var i = 0; i < _results.Count; i++)
        {
            if (ReferenceEquals(_results[i], result))
            {
                return i;
            }
        }

        return -1;
    }

    public void Dispose() => _disposed = true;

    public IEnumerator GetEnumerator() => ((IEnumerable)_results).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    IEnumerator<SearchResult> IEnumerable<SearchResult>.GetEnumerator() => _results.GetEnumerator();

    bool ICollection.IsSynchronized => false;

    object ICollection.SyncRoot => this;

    void ICollection.CopyTo(Array array, int index)
    {
        for (var i = 0; i < _results.Count; i++)
        {
            array.SetValue(_results[i], index + i);
        }
    }
}
