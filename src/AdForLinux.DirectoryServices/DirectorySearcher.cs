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

    /// <summary>Creates a searcher with a filter and properties to retrieve.</summary>
    public DirectorySearcher(string filter, string[] propertiesToLoad)
        : this(null, filter, propertiesToLoad, SearchScope.Subtree)
    {
    }

    /// <summary>Creates a searcher with a filter, properties, and scope.</summary>
    public DirectorySearcher(string filter, string[] propertiesToLoad, SearchScope searchScope)
        : this(null, filter, propertiesToLoad, searchScope)
    {
    }

    /// <summary>Creates a searcher with a root, filter, and properties.</summary>
    public DirectorySearcher(DirectoryEntry? searchRoot, string filter, string[] propertiesToLoad)
        : this(searchRoot, filter, propertiesToLoad, SearchScope.Subtree)
    {
    }

    /// <summary>Creates a searcher with a root, filter, properties, and scope.</summary>
    public DirectorySearcher(
        DirectoryEntry? searchRoot,
        string filter,
        string[] propertiesToLoad,
        SearchScope searchScope)
    {
        ArgumentNullException.ThrowIfNull(propertiesToLoad);
        SearchRoot = searchRoot;
        Filter = filter;
        SearchScope = searchScope;
        PropertiesToLoad.AddRange(propertiesToLoad);
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

    /// <summary>Gets or sets whether the provider performs asynchronous searches.</summary>
    public bool Asynchronous { get; set; }

    /// <summary>Gets or sets the LDAP attribute used for ADSI attribute-scoped queries.</summary>
    public string? AttributeScopeQuery { get; set; }

    /// <summary>Gets or sets whether returned results are cached by the provider.</summary>
    public bool CacheResults { get; set; } = true;

    /// <summary>Gets or sets the maximum time the client waits for a response.</summary>
    public TimeSpan ClientTimeout { get; set; } = Timeout.InfiniteTimeSpan;

    /// <summary>Gets or sets how LDAP aliases are dereferenced.</summary>
    public DereferenceAlias DerefAlias { get; set; }

    /// <summary>Gets or sets the optional directory synchronization configuration.</summary>
    public DirectorySynchronization? DirectorySynchronization { get; set; }

    /// <summary>Gets or sets the extended-DN format requested from the server.</summary>
    public ExtendedDN ExtendedDN { get; set; }

    /// <summary>Gets or sets whether only property names, rather than values, are returned.</summary>
    public bool PropertyNamesOnly { get; set; }

    /// <summary>Gets or sets the referral-chasing behavior.</summary>
    public ReferralChasingOption ReferralChasing { get; set; } = ReferralChasingOption.External;

    /// <summary>Gets or sets the requested security descriptor sections.</summary>
    public SecurityMasks SecurityMasks { get; set; }

    /// <summary>Gets or sets the server time limit for each page.</summary>
    public TimeSpan ServerPageTimeLimit { get; set; } = Timeout.InfiniteTimeSpan;

    /// <summary>Gets or sets the server time limit for the search.</summary>
    public TimeSpan ServerTimeLimit { get; set; } = Timeout.InfiniteTimeSpan;

    /// <summary>Gets or sets the optional server-side sort.</summary>
    public SortOption? Sort { get; set; }

    /// <summary>Gets or sets whether deleted objects are included.</summary>
    public bool Tombstone { get; set; }

    /// <summary>Gets or sets the optional virtual-list-view configuration.</summary>
    public DirectoryVirtualListView? VirtualListView { get; set; }

    /// <summary>Returns the first match, or null if there is none.</summary>
    public SearchResult? FindOne()
    {
        var root = RequireRoot();
        var request = BuildRequest();
        request.SizeLimit = 1;

        var connection = root.GetConnection();
        ConfigureConnection(connection);
        var response = SendSearch(connection, request);
        UpdateControlState(response);
        return response.Entries.Count > 0
            ? new SearchResult(response.Entries[0], root)
            : null;
    }

    /// <summary>Returns every match. Pages automatically when PageSize &gt; 0.</summary>
    public SearchResultCollection FindAll()
    {
        var root = RequireRoot();
        var connection = root.GetConnection();
        ConfigureConnection(connection);
        var results = new List<SearchResult>();

        if (PageSize > 0)
        {
            var pageControl = new PageResultRequestControl(PageSize);
            while (true)
            {
                var request = BuildRequest();
                request.Controls.Add(pageControl);
                var response = SendSearch(connection, request);
                UpdateControlState(response);

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
            UpdateControlState(response);
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

        if (!string.IsNullOrWhiteSpace(AttributeScopeQuery))
        {
            throw new PlatformNotSupportedException(
                "AttributeScopeQuery is an ADSI-specific search mode with no portable LDAP equivalent.");
        }

        var request = new SearchRequest(
            root.DistinguishedName,
            string.IsNullOrEmpty(Filter) ? "(objectClass=*)" : Filter,
            ToProtocolScope(SearchScope),
            attributes);

        request.Aliases = (System.DirectoryServices.Protocols.DereferenceAlias)(int)DerefAlias;
        request.TypesOnly = PropertyNamesOnly;

        var timeLimit = ServerTimeLimit != Timeout.InfiniteTimeSpan
            ? ServerTimeLimit
            : ServerPageTimeLimit;
        if (timeLimit != Timeout.InfiniteTimeSpan)
        {
            request.TimeLimit = timeLimit;
        }

        if (ExtendedDN != ExtendedDN.None)
        {
            request.Controls.Add(new ExtendedDNControl((ExtendedDNFlag)(int)ExtendedDN));
        }

        if (Sort?.PropertyName is { Length: > 0 } sortProperty)
        {
            request.Controls.Add(new SortRequestControl(sortProperty, Sort.Direction == SortDirection.Descending));
        }

        if (DirectorySynchronization is not null)
        {
            request.Controls.Add(DirectorySynchronization.CreateControl());
        }

        if (VirtualListView is not null)
        {
            request.Controls.Add(VirtualListView.CreateControl());
        }

        if (Tombstone)
        {
            request.Controls.Add(new ShowDeletedControl());
        }

        if (SecurityMasks != SecurityMasks.None)
        {
            request.Controls.Add(new SecurityDescriptorFlagControl(
                (System.DirectoryServices.Protocols.SecurityMasks)(int)SecurityMasks));
        }

        if (SizeLimit > 0)
        {
            request.SizeLimit = SizeLimit;
        }

        return request;
    }

    private DirectoryEntry RequireRoot() =>
        SearchRoot ?? throw new InvalidOperationException(
            "SearchRoot must be set before searching. Serverless search is not supported on Linux.");

    private SearchResponse SendSearch(LdapConnection connection, SearchRequest request)
    {
        var originalTimeout = connection.Timeout;
        try
        {
            if (ClientTimeout != Timeout.InfiniteTimeSpan)
            {
                connection.Timeout = ClientTimeout;
            }

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
        finally
        {
            connection.Timeout = originalTimeout;
        }
    }

    private void ConfigureConnection(LdapConnection connection)
    {
        // The native Linux LDAP implementation accepts only None and All.
        // Keep the ADSI-compatible partial modes on Windows, and degrade them
        // to All only where the underlying runtime cannot represent them.
        connection.SessionOptions.ReferralChasing = OperatingSystem.IsWindows()
            ? (ReferralChasingOptions)(int)ReferralChasing
            : ReferralChasing switch
        {
            ReferralChasingOption.None => ReferralChasingOptions.None,
            _ => ReferralChasingOptions.All,
        };
    }

    private void UpdateControlState(SearchResponse response)
    {
        if (DirectorySynchronization is not null && response.Controls.OfType<DirSyncResponseControl>().FirstOrDefault() is { } sync)
        {
            DirectorySynchronization.Update(sync);
        }

        if (VirtualListView is not null && response.Controls.OfType<VlvResponseControl>().FirstOrDefault() is { } vlv)
        {
            VirtualListView.Update(vlv);
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
