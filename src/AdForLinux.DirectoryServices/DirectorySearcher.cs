using System.Collections.Specialized;
using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Searches the directory under a root entry, like Microsoft's
/// <c>DirectorySearcher</c>. Set <see cref="Filter"/> and
/// <see cref="PropertiesToLoad"/>, then call <see cref="FindOne"/> or
/// <see cref="FindAll"/>.
/// </summary>
public class DirectorySearcher : IDisposable
{
    /// <summary>Creates a searcher with no root yet.</summary>
    public DirectorySearcher()
    {
    }

    /// <summary>Creates a searcher rooted at an entry.</summary>
    public DirectorySearcher(DirectoryEntry? searchRoot)
    {
        SearchRoot = searchRoot;
    }

    /// <summary>Creates a searcher rooted at an entry with a filter.</summary>
    public DirectorySearcher(DirectoryEntry? searchRoot, string filter)
    {
        SearchRoot = searchRoot;
        Filter = filter;
    }

    /// <summary>The entry the search starts from. Required before searching.</summary>
    public DirectoryEntry? SearchRoot { get; set; }

    /// <summary>The LDAP filter, e.g. <c>(&amp;(objectClass=user)(cn=jeff))</c>.</summary>
    public string Filter { get; set; } = "(objectClass=*)";

    /// <summary>How deep to search. Subtree by default.</summary>
    public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

    /// <summary>Attributes to return. Empty means all.</summary>
    public StringCollection PropertiesToLoad { get; } = new();

    /// <summary>Page size for <see cref="FindAll"/>. 0 turns paging off.</summary>
    public int PageSize { get; set; }

    /// <summary>Server-side cap on results. 0 means the server default.</summary>
    public int SizeLimit { get; set; }

    /// <summary>Returns the first match, or null if there is none.</summary>
    public SearchResult? FindOne()
    {
        var root = RequireRoot();
        var request = BuildRequest();
        request.SizeLimit = 1;

        var response = SendSearch(root.GetConnection(), request);
        return response.Entries.Count > 0
            ? new SearchResult(response.Entries[0], root)
            : null;
    }

    /// <summary>Returns every match. Pages automatically when PageSize &gt; 0.</summary>
    public SearchResultCollection FindAll()
    {
        var root = RequireRoot();
        var connection = root.GetConnection();
        var results = new List<SearchResult>();

        if (PageSize > 0)
        {
            var pageControl = new PageResultRequestControl(PageSize);
            while (true)
            {
                var request = BuildRequest();
                request.Controls.Add(pageControl);
                var response = SendSearch(connection, request);

                foreach (SearchResultEntry entry in response.Entries)
                {
                    results.Add(new SearchResult(entry, root));
                }

                var cookie = response.Controls
                    .OfType<PageResultResponseControl>()
                    .FirstOrDefault()?.Cookie;

                if (cookie is null || cookie.Length == 0)
                {
                    break;
                }

                pageControl.Cookie = cookie;
            }
        }
        else
        {
            var response = SendSearch(connection, BuildRequest());
            foreach (SearchResultEntry entry in response.Entries)
            {
                results.Add(new SearchResult(entry, root));
            }
        }

        return new SearchResultCollection(results);
    }

    private SearchRequest BuildRequest()
    {
        var root = RequireRoot();
        var attributes = PropertiesToLoad.Count > 0
            ? PropertiesToLoad.Cast<string>().ToArray()
            : Array.Empty<string>();

        var request = new SearchRequest(
            root.DistinguishedName,
            string.IsNullOrEmpty(Filter) ? "(objectClass=*)" : Filter,
            ToProtocolScope(SearchScope),
            attributes);

        if (SizeLimit > 0)
        {
            request.SizeLimit = SizeLimit;
        }

        return request;
    }

    private DirectoryEntry RequireRoot() =>
        SearchRoot ?? throw new InvalidOperationException(
            "SearchRoot must be set before searching. Serverless search is not supported on Linux.");

    private static SearchResponse SendSearch(LdapConnection connection, SearchRequest request)
    {
        try
        {
            return (SearchResponse)connection.SendRequest(request);
        }
        catch (DirectoryOperationException ex)
            when (ex.Response is SearchResponse partial &&
                  partial.ResultCode == ResultCode.SizeLimitExceeded)
        {
            // FindOne / SizeLimit ask for fewer results than exist; the server
            // returns what it has plus this code. That is expected, not an error.
            return partial;
        }
    }

    private static ProtocolScope ToProtocolScope(SearchScope scope) => scope switch
    {
        SearchScope.Base => ProtocolScope.Base,
        SearchScope.OneLevel => ProtocolScope.OneLevel,
        _ => ProtocolScope.Subtree,
    };

    public void Dispose() => GC.SuppressFinalize(this);
}
