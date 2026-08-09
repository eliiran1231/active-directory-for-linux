using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
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
    private SearchScope _searchScope = SearchScope.Subtree;
    private bool _searchScopeSpecified;
    private string _attributeScopeQuery = string.Empty;

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
        _searchScopeSpecified = false;
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
        _searchScopeSpecified = false;
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
    public SearchScope SearchScope
    {
        get => _searchScope;
        set
        {
            if (value < SearchScope.Base || value > SearchScope.Subtree)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(SearchScope));
            }

            if (!string.IsNullOrEmpty(_attributeScopeQuery) && value != SearchScope.Base)
            {
                throw new ArgumentException(
                    "SearchScope must be Base when AttributeScopeQuery is set.", nameof(value));
            }

            _searchScope = value;
            _searchScopeSpecified = true;
        }
    }

    /// <summary>Attributes to return. Empty means all.</summary>
    public StringCollection PropertiesToLoad { get; } = new();

    /// <summary>Page size for <see cref="FindAll"/>. 0 turns paging off.</summary>
    public int PageSize { get; set; }

    /// <summary>Server-side cap on results. 0 means the server default.</summary>
    public int SizeLimit { get; set; }

    /// <summary>Gets or sets whether the provider performs asynchronous searches.</summary>
    public bool Asynchronous { get; set; }

    /// <summary>Gets or sets the LDAP attribute used for ADSI attribute-scoped queries.</summary>
    [AllowNull]
    public string AttributeScopeQuery
    {
        get => _attributeScopeQuery;
        set
        {
            value ??= string.Empty;
            if (value.Length > 0)
            {
                if (_searchScopeSpecified && SearchScope != SearchScope.Base)
                {
                    throw new ArgumentException(
                        "SearchScope must be Base when AttributeScopeQuery is set.", nameof(value));
                }

                _searchScope = SearchScope.Base;
            }

            _attributeScopeQuery = value;
        }
    }

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
        if (HasAttributeScopeQuery)
        {
            return FindAttributeScoped(root, maximumResults: 1).FirstOrDefault();
        }

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
        if (HasAttributeScopeQuery)
        {
            var maximumResults = SizeLimit > 0 ? SizeLimit : int.MaxValue;
            return new SearchResultCollection(FindAttributeScoped(root, maximumResults));
        }

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

    private bool HasAttributeScopeQuery => _attributeScopeQuery.Length > 0;

    private List<SearchResult> FindAttributeScoped(DirectoryEntry root, int maximumResults)
    {
        var connection = root.GetConnection();
        ConfigureConnection(connection);

        // Samba accepts ASQ controls for non-DN attributes instead of returning
        // AD's invalidAttributeSyntax (21), so validate against attributeSchema
        // before either the native or emulated execution path.
        AdForLinux.DirectoryServices.Ldap.LdapAttributeSchema
            .EnsureDistinguishedNameAttribute(connection, _attributeScopeQuery);

        var nativeResults = TryNativeAttributeScopeQuery(connection, root, maximumResults);
        if (nativeResults is not null)
        {
            return nativeResults;
        }

        // Non-AD LDAP servers may not implement LDAP_SERVER_ASQ_OID. The
        // compatibility fallback follows each reference separately. The schema
        // validation above prevents ordinary strings from being treated as DNs.

        var referencedDns = ReadAttributeScopeDns(connection, root.DistinguishedName);
        if (referencedDns.Count == 0 || maximumResults == 0)
        {
            return new List<SearchResult>();
        }

        var results = new List<SearchResult>();
        foreach (var distinguishedName in referencedDns)
        {
            var request = BuildRequest(distinguishedName);
            request.Scope = ProtocolScope.Base;
            request.SizeLimit = 1;

            SearchResponse response;
            try
            {
                response = SendSearch(connection, request);
            }
            catch (DirectoryOperationException ex)
                when (ex.Response.ResultCode == ResultCode.NoSuchObject)
            {
                // A stale DN-valued reference behaves like an ASQ row that no
                // longer resolves: it contributes no result.
                continue;
            }

            UpdateControlState(response);
            if (response.Entries.Count == 0)
            {
                continue;
            }

            results.Add(new SearchResult(response.Entries[0], root));
            if (results.Count >= maximumResults)
            {
                break;
            }
        }

        return results;
    }

    private List<SearchResult>? TryNativeAttributeScopeQuery(
        LdapConnection connection,
        DirectoryEntry root,
        int maximumResults)
    {
        var request = BuildRequest();
        request.Scope = ProtocolScope.Base;
        if (maximumResults != int.MaxValue)
        {
            request.SizeLimit = maximumResults;
        }

        request.Controls.Add(new AsqRequestControl(_attributeScopeQuery)
        {
            IsCritical = true,
        });

        SearchResponse response;
        try
        {
            response = SendSearch(connection, request);
        }
        catch (DirectoryOperationException ex)
            when (ex.Response.ResultCode == ResultCode.UnavailableCriticalExtension)
        {
            return null;
        }

        var asq = response.Controls.OfType<AsqResponseControl>().FirstOrDefault();
        if (asq is null)
        {
            return null;
        }

        if (asq.Result == ResultCode.UnavailableCriticalExtension)
        {
            return null;
        }

        if (asq.Result is not ResultCode.Success and not ResultCode.SizeLimitExceeded)
        {
            throw new DirectoryOperationException(
                $"AttributeScopeQuery failed with LDAP {asq.Result} ({(int)asq.Result}).");
        }

        UpdateControlState(response);
        return response.Entries
            .Cast<SearchResultEntry>()
            .Take(maximumResults)
            .Select(entry => new SearchResult(entry, root))
            .ToList();
    }

    private List<string> ReadAttributeScopeDns(LdapConnection connection, string rootDistinguishedName)
    {
        var values = new List<string>();
        var requestedAttribute = _attributeScopeQuery;

        while (true)
        {
            var request = new SearchRequest(
                rootDistinguishedName,
                "(objectClass=*)",
                ProtocolScope.Base,
                requestedAttribute);
            var response = SendSearch(connection, request);
            if (response.Entries.Count == 0)
            {
                break;
            }

            var returnedAttribute = response.Entries[0].Attributes.AttributeNames
                .Cast<string>()
                .FirstOrDefault(name =>
                    name.Equals(_attributeScopeQuery, StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith($"{_attributeScopeQuery};range=", StringComparison.OrdinalIgnoreCase));
            if (returnedAttribute is null)
            {
                break;
            }

            var attribute = response.Entries[0].Attributes[returnedAttribute];
            foreach (var value in attribute.GetValues(typeof(string)))
            {
                values.Add((string)value);
            }

            var rangeMarker = returnedAttribute.IndexOf(";range=", StringComparison.OrdinalIgnoreCase);
            if (rangeMarker < 0 || returnedAttribute.EndsWith("-*", StringComparison.Ordinal))
            {
                break;
            }

            var range = returnedAttribute[(rangeMarker + ";range=".Length)..];
            var separator = range.IndexOf('-');
            if (separator < 0 || !int.TryParse(range[(separator + 1)..], out var end))
            {
                throw new DirectoryOperationException(
                    $"Directory server returned an invalid attribute range '{returnedAttribute}'.");
            }

            requestedAttribute = $"{_attributeScopeQuery};range={end + 1}-*";
        }

        return values;
    }

    private SearchRequest BuildRequest(string distinguishedName)
    {
        var request = BuildRequest();
        request.DistinguishedName = distinguishedName;
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
