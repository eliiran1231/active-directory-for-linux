using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The results of <see cref="DirectorySearcher.FindAll"/>, like Microsoft's
/// <c>SearchResultCollection</c>.
/// </summary>
public sealed class SearchResultCollection : IReadOnlyList<SearchResult>
{
    private readonly IReadOnlyList<SearchResult> _results;

    internal SearchResultCollection(IReadOnlyList<SearchResult> results)
    {
        _results = results;
    }

    public SearchResult this[int index] => _results[index];

    public int Count => _results.Count;

    public IEnumerator<SearchResult> GetEnumerator() => _results.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
