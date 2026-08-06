using System.Collections;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The results of a principal search, like Microsoft's
/// <c>PrincipalSearchResult&lt;T&gt;</c>. Enumerate it to read the matches.
/// </summary>
public sealed class PrincipalSearchResult<T> : IEnumerable<T>, IDisposable
    where T : Principal
{
    private readonly IReadOnlyList<T> _results;

    internal PrincipalSearchResult(IReadOnlyList<T> results)
    {
        _results = results;
    }

    public IEnumerator<T> GetEnumerator() => _results.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public void Dispose()
    {
        foreach (var result in _results)
        {
            result.Dispose();
        }
    }
}
