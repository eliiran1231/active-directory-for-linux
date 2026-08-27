using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Searches the directory under a root entry, like Microsoft's
/// <c>DirectorySearcher</c>. Set <see cref="Filter"/> and
/// <see cref="PropertiesToLoad"/>, then call <see cref="FindOne"/> or
/// <see cref="FindAll"/>.
/// </summary>
public class DirectorySearcher : Component
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(-1);

    private bool _cacheResults = true;
    private bool _cacheResultsSpecified;
    private TimeSpan _clientTimeout = DefaultTimeout;
    private DereferenceAlias _derefAlias;
    private DirectorySynchronization? _directorySynchronization;
    private ExtendedDN _extendedDn = ExtendedDN.None;
    private string _filter = "(objectClass=*)";
    private SearchScope _searchScope = SearchScope.Subtree;
    private bool _searchScopeSpecified;
    private string _attributeScopeQuery = string.Empty;
    private int _pageSize;
    private ReferralChasingOption _referralChasing = ReferralChasingOption.External;
    private TimeSpan _serverPageTimeLimit = DefaultTimeout;
    private TimeSpan _serverTimeLimit = DefaultTimeout;
    private int _sizeLimit;
    private SortOption _sort = new();
    private SecurityMasks _securityMasks;
    private DirectoryVirtualListView? _virtualListView;

    internal TimeProvider TimeProvider { get; set; } = TimeProvider.System;

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
    public DirectorySearcher(DirectoryEntry? searchRoot, string? filter)
    {
        SearchRoot = searchRoot;
        Filter = filter;
    }

    /// <summary>Creates a searcher with a filter and no root yet.</summary>
    public DirectorySearcher(string? filter)
        : this(null, filter)
    {
    }

    /// <summary>Creates a searcher with a filter and properties to retrieve.</summary>
    public DirectorySearcher(string? filter, string[]? propertiesToLoad)
        : this(null, filter, propertiesToLoad, SearchScope.Subtree)
    {
        _searchScopeSpecified = false;
    }

    /// <summary>Creates a searcher with a filter, properties, and scope.</summary>
    public DirectorySearcher(string? filter, string[]? propertiesToLoad, SearchScope scope)
        : this(null, filter, propertiesToLoad, scope)
    {
    }

    /// <summary>Creates a searcher with a root, filter, and properties.</summary>
    public DirectorySearcher(DirectoryEntry? searchRoot, string? filter, string[]? propertiesToLoad)
        : this(searchRoot, filter, propertiesToLoad, SearchScope.Subtree)
    {
        _searchScopeSpecified = false;
    }

    /// <summary>Creates a searcher with a root, filter, properties, and scope.</summary>
    public DirectorySearcher(
        DirectoryEntry? searchRoot,
        string? filter,
        string[]? propertiesToLoad,
        SearchScope scope)
    {
        SearchRoot = searchRoot;
        Filter = filter;
        SearchScope = scope;
        if (propertiesToLoad is not null)
        {
            PropertiesToLoad.AddRange(propertiesToLoad);
        }
    }

    /// <summary>The entry the search starts from. Required before searching.</summary>
    [DefaultValue(null)]
    public DirectoryEntry? SearchRoot { get; set; }

    /// <summary>The LDAP filter, e.g. <c>(&amp;(objectClass=user)(cn=jeff))</c>.</summary>
    [AllowNull]
    [DefaultValue("(objectClass=*)")]
    public string Filter
    {
        get => _filter;
        set => _filter = string.IsNullOrEmpty(value) ? "(objectClass=*)" : value;
    }

    /// <summary>How deep to search. Subtree by default.</summary>
    [DefaultValue(SearchScope.Subtree)]
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
    [Editor(
        "System.Windows.Forms.Design.StringCollectionEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
    public StringCollection PropertiesToLoad { get; } = new();

    /// <summary>Page size for <see cref="FindAll"/>. 0 turns paging off.</summary>
    [DefaultValue(0)]
    public int PageSize
    {
        get => _pageSize;
        set
        {
            if (value < 0)
            {
                throw new ArgumentException(
                    "The PageSize must be greater than 0 or set to 0 for no paging.", nameof(value));
            }

            if (value != 0 && DirectorySynchronization is not null)
            {
                throw new ArgumentException("DirectorySynchronization cannot be combined with PageSize.");
            }

            _pageSize = value;
        }
    }

    /// <summary>Server-side cap on results. 0 means the server default.</summary>
    [DefaultValue(0)]
    public int SizeLimit
    {
        get => _sizeLimit;
        set
        {
            if (value < 0)
            {
                throw new ArgumentException("SizeLimit must be greater than or equal to 0.", nameof(value));
            }

            _sizeLimit = value;
        }
    }

    /// <summary>
    /// Gets or sets whether <see cref="FindAll"/> streams LDAP results as they arrive.
    /// <see cref="FindOne"/> remains synchronous because its public contract returns one value.
    /// </summary>
    [DefaultValue(false)]
    public bool Asynchronous { get; set; }

    /// <summary>Gets or sets the LDAP attribute used for ADSI attribute-scoped queries.</summary>
    [AllowNull]
    [DefaultValue("")]
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

    /// <summary>
    /// Gets or sets whether <see cref="FindAll"/> retains results for repeated enumeration.
    /// When false, direct enumeration is forward-only; collection operations such as
    /// <see cref="SearchResultCollection.Count"/> explicitly materialize the remaining results.
    /// </summary>
    [DefaultValue(true)]
    public bool CacheResults
    {
        get => _cacheResults;
        set
        {
            if (value && VirtualListView is not null)
            {
                throw new ArgumentException("VirtualListView cannot be combined with CacheResults.");
            }

            _cacheResults = value;
            _cacheResultsSpecified = true;
        }
    }

    /// <summary>Gets or sets the maximum time the client waits for a response.</summary>
    public TimeSpan ClientTimeout
    {
        get => _clientTimeout;
        set
        {
            ValidateTimeout(value);
            _clientTimeout = value;
        }
    }

    /// <summary>Gets or sets how LDAP aliases are dereferenced.</summary>
    [DefaultValue(DereferenceAlias.Never)]
    public DereferenceAlias DerefAlias
    {
        get => _derefAlias;
        set
        {
            if (value < DereferenceAlias.Never || value > DereferenceAlias.Always)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(DereferenceAlias));
            }

            _derefAlias = value;
        }
    }

    /// <summary>Gets or sets the optional directory synchronization configuration.</summary>
    [DefaultValue(null)]
    public DirectorySynchronization? DirectorySynchronization
    {
        get => _directorySynchronization;
        set
        {
            if (value is not null && PageSize != 0)
            {
                throw new ArgumentException("DirectorySynchronization cannot be combined with PageSize.");
            }

            _directorySynchronization = value;
        }
    }

    /// <summary>Gets or sets the extended-DN format requested from the server.</summary>
    [DefaultValue(ExtendedDN.None)]
    public ExtendedDN ExtendedDN
    {
        get => _extendedDn;
        set
        {
            if (value < ExtendedDN.None || value > ExtendedDN.Standard)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ExtendedDN));
            }

            _extendedDn = value;
        }
    }

    /// <summary>Gets or sets whether only property names, rather than values, are returned.</summary>
    [DefaultValue(false)]
    public bool PropertyNamesOnly { get; set; }

    /// <summary>Gets or sets the referral-chasing behavior.</summary>
    [DefaultValue(ReferralChasingOption.External)]
    public ReferralChasingOption ReferralChasing
    {
        get => _referralChasing;
        set
        {
            if (value is not ReferralChasingOption.None and
                not ReferralChasingOption.Subordinate and
                not ReferralChasingOption.External and
                not ReferralChasingOption.All)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ReferralChasingOption));
            }

            _referralChasing = value;
        }
    }

    /// <summary>Gets or sets the requested security descriptor sections.</summary>
    [DefaultValue(SecurityMasks.None)]
    public SecurityMasks SecurityMasks
    {
        get => _securityMasks;
        set
        {
            const SecurityMasks allMasks =
                SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
            if (value > allMasks)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(SecurityMasks));
            }

            _securityMasks = value;
        }
    }

    /// <summary>Gets or sets the server time limit for each page.</summary>
    public TimeSpan ServerPageTimeLimit
    {
        get => _serverPageTimeLimit;
        set
        {
            ValidateTimeout(value);
            _serverPageTimeLimit = value;
        }
    }

    /// <summary>Gets or sets the server time limit for the search.</summary>
    public TimeSpan ServerTimeLimit
    {
        get => _serverTimeLimit;
        set
        {
            ValidateTimeout(value);
            _serverTimeLimit = value;
        }
    }

    /// <summary>Gets or sets the optional server-side sort.</summary>
    [TypeConverter(typeof(ExpandableObjectConverter))]
    public SortOption Sort
    {
        get => _sort;
        set => _sort = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>Gets or sets whether deleted objects are included.</summary>
    [DefaultValue(false)]
    public bool Tombstone { get; set; }

    /// <summary>Gets or sets the optional virtual-list-view configuration.</summary>
    [DefaultValue(null)]
    public DirectoryVirtualListView? VirtualListView
    {
        get => _virtualListView;
        set
        {
            if (value is not null)
            {
                if (_cacheResultsSpecified && CacheResults)
                {
                    throw new ArgumentException("VirtualListView cannot be combined with CacheResults.");
                }

                _cacheResults = false;
            }

            _virtualListView = value;
        }
    }

    /// <summary>Returns the first match, or null if there is none.</summary>
    public SearchResult? FindOne()
    {
        var configuredRoot = RequireRoot();
        using var reboundRoot = configuredRoot.IsDisposed
            ? configuredRoot.CreateEntryForDn(configuredRoot.DistinguishedName)
            : null;
        var root = reboundRoot ?? configuredRoot;
        if (HasAttributeScopeQuery)
        {
            return FindAttributeScoped(root, maximumResults: 1).FirstOrDefault();
        }

        var request = BuildRequest();
        request.SizeLimit = 1;

        CreateServerTimeLimitBudget(isPaged: false).TryApply(request);

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
        var configuredRoot = RequireRoot();
        using var reboundRoot = configuredRoot.IsDisposed
            ? configuredRoot.CreateEntryForDn(configuredRoot.DistinguishedName)
            : null;
        var root = reboundRoot ?? configuredRoot;
        if (HasAttributeScopeQuery)
        {
            var maximumResults = SizeLimit > 0 ? SizeLimit : int.MaxValue;
            return new SearchResultCollection(
                FindAttributeScoped(root, maximumResults), CacheResults, GetPropertiesLoaded());
        }

        if (Asynchronous || !CacheResults)
        {
            return FindAllStreaming(root);
        }

        var connection = root.GetConnection();
        ConfigureConnection(connection);
        var results = new List<SearchResult>();
        var timeLimitBudget = CreateServerTimeLimitBudget(PageSize > 0);

        if (PageSize > 0)
        {
            var pageControl = new PageResultRequestControl(PageSize);
            while (true)
            {
                var request = BuildRequest();
                request.Controls.Add(pageControl);
                if (!timeLimitBudget.TryApply(request))
                {
                    break;
                }

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
            var request = BuildRequest();
            timeLimitBudget.TryApply(request);
            var response = SendSearch(connection, request);
            UpdateControlState(response);
            foreach (SearchResultEntry entry in response.Entries)
            {
                results.Add(new SearchResult(entry, root));
            }
        }

        return new SearchResultCollection(results, GetPropertiesLoaded());
    }

    private SearchResultCollection FindAllStreaming(DirectoryEntry root)
    {
        // Use a separate connection because a result collection can outlive the searcher/root,
        // and an in-flight request must not share mutable timeout/referral state with callers.
        var resultRoot = root.CreateEntryForDn(root.DistinguishedName);
        var connection = resultRoot.GetConnection();
        ConfigureConnection(connection);
        var request = BuildRequest();
        var pageControl = PageSize > 0 ? new PageResultRequestControl(PageSize) : null;
        if (pageControl is not null)
        {
            request.Controls.Add(pageControl);
        }

        var returnPartialResults = Asynchronous;
        var timeout = ClientTimeout;
        var source = new StreamingSearchResultSource((add, cancellationToken) =>
        {
            try
            {
                var timeLimitBudget = CreateServerTimeLimitBudget(pageControl is not null);
                while (true)
                {
                    if (!timeLimitBudget.TryApply(request))
                    {
                        break;
                    }

                    var response = SendSearchAsynchronously(
                        connection, request, resultRoot, returnPartialResults, timeout, add, cancellationToken);
                    UpdateControlState(response);

                    if (pageControl is null)
                    {
                        break;
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
            finally
            {
                resultRoot.Dispose();
            }
        });

        return new SearchResultCollection(source, CacheResults, GetPropertiesLoaded());
    }

    private static SearchResponse SendSearchAsynchronously(
        LdapConnection connection,
        SearchRequest request,
        DirectoryEntry resultRoot,
        bool returnPartialResults,
        TimeSpan timeout,
        Action<SearchResult> add,
        CancellationToken cancellationToken)
    {
        var partialMode = returnPartialResults
            ? PartialResultProcessing.ReturnPartialResults
            : PartialResultProcessing.NoPartialResultSupport;
        var returnedDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddEntries(System.Collections.IEnumerable entries)
        {
            foreach (var item in entries)
            {
                if (item is SearchResultEntry entry && returnedDns.Add(entry.DistinguishedName))
                {
                    add(new SearchResult(entry, resultRoot));
                }
            }
        }

        try
        {
            var asyncResult = timeout >= TimeSpan.Zero
                ? connection.BeginSendRequest(request, timeout, partialMode, null, null)
                : connection.BeginSendRequest(request, partialMode, null, null);

            while (!asyncResult.IsCompleted)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    connection.Abort(asyncResult);
                    cancellationToken.ThrowIfCancellationRequested();
                }

                if (returnPartialResults)
                {
                    AddEntries(connection.GetPartialResults(asyncResult));
                }

                asyncResult.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(50));
            }

            if (returnPartialResults)
            {
                AddEntries(connection.GetPartialResults(asyncResult));
            }

            var response = (SearchResponse)connection.EndSendRequest(asyncResult);
            AddEntries(response.Entries);
            return response;
        }
        catch (DirectoryOperationException ex)
            when (ex.Response is SearchResponse partial &&
                  partial.ResultCode == ResultCode.SizeLimitExceeded)
        {
            AddEntries(partial.Entries);
            return partial;
        }
        catch (LdapException ex) when (ex.ErrorCode == 87)
        {
            throw new ArgumentException(ex.Message, nameof(Filter), ex);
        }
        catch (Exception exception) when (LdapExceptionTranslator.IsProtocolFailure(exception))
        {
            throw LdapExceptionTranslator.Translate(exception);
        }
    }

    private string[] GetPropertiesLoaded() => PropertiesToLoad.Cast<string>().ToArray();

    private SearchRequest BuildRequest()
    {
        var root = RequireRoot();
#if NET10_0_OR_GREATER
        if (!IsStructurallyValidFilter(Filter))
        {
            var protocol = new LdapException(87, "The search filter is invalid.");
            throw new ArgumentException(protocol.Message, nameof(Filter), protocol);
        }
#endif
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

        // ServerPageTimeLimit applies only to paged searches. Paged callers
        // replace this initial value with the per-page limit and remaining
        // overall search budget immediately before each request is sent.
        if (ServerTimeLimit >= TimeSpan.Zero)
        {
            request.TimeLimit = ServerTimeLimit;
        }

        if (ExtendedDN != ExtendedDN.None)
        {
            request.Controls.Add(new ExtendedDNControl((ExtendedDNFlag)(int)ExtendedDN));
        }

        if (Sort.PropertyName is { Length: > 0 } sortProperty)
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

    private ServerSearchTimeLimitBudget CreateServerTimeLimitBudget(bool isPaged) =>
        new(ServerTimeLimit, ServerPageTimeLimit, isPaged, TimeProvider);

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
            catch (DirectoryServicesCOMException ex)
                when (ex.ErrorCode == unchecked((int)0x80072030))
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
        catch (DirectoryServicesCOMException ex)
            when (ex.ErrorCode == unchecked((int)0x8007202C))
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
            throw LdapExceptionTranslator.Translate(
                asq.Result,
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
                throw LdapExceptionTranslator.Translate(
                    ResultCode.ProtocolError,
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

    private DirectoryEntry RequireRoot()
    {
        return SearchRoot ?? throw new InvalidOperationException(
            "SearchRoot must be set before searching. Serverless search is not supported on Linux.");
    }

#if NET10_0_OR_GREATER
    private static bool IsStructurallyValidFilter(string filter)
    {
        var index = 0;
        return ParseFilter(filter, ref index) && index == filter.Length;
    }

    private static bool ParseFilter(string filter, ref int index)
    {
        if (index >= filter.Length || filter[index++] != '(' || index >= filter.Length)
        {
            return false;
        }

        if (filter[index] is '&' or '|')
        {
            index++;
            var operands = 0;
            while (index < filter.Length && filter[index] == '(')
            {
                if (!ParseFilter(filter, ref index))
                {
                    return false;
                }

                operands++;
            }

            return operands > 0 && index < filter.Length && filter[index++] == ')';
        }

        if (filter[index] == '!')
        {
            index++;
            return ParseFilter(filter, ref index) &&
                index < filter.Length && filter[index++] == ')';
        }

        var hasComparison = false;
        while (index < filter.Length && filter[index] != ')')
        {
            if (filter[index] == '(')
            {
                return false;
            }

            if (filter[index] == '\\')
            {
                index++;
                if (index >= filter.Length)
                {
                    return false;
                }

                index++;
                continue;
            }

            hasComparison |= filter[index] == '=';
            index++;
        }

        return hasComparison && index < filter.Length && filter[index++] == ')';
    }
#endif

    private SearchResponse SendSearch(LdapConnection connection, SearchRequest request)
    {
        var originalTimeout = connection.Timeout;
        try
        {
            if (ClientTimeout >= TimeSpan.Zero)
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
        catch (LdapException ex) when (ex.ErrorCode == 87)
        {
            throw new ArgumentException(ex.Message, nameof(Filter), ex);
        }
        catch (Exception exception) when (LdapExceptionTranslator.IsProtocolFailure(exception))
        {
            throw LdapExceptionTranslator.Translate(exception);
        }
        finally
        {
            connection.Timeout = originalTimeout;
        }
    }

    private void ConfigureConnection(LdapConnection connection)
    {
        LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasing);
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

    private static void ValidateTimeout(TimeSpan value)
    {
        if (value.TotalSeconds > int.MaxValue)
        {
            throw new ArgumentException("The value exceeds the maximum allowed.", nameof(value));
        }
    }

    /// <summary>Releases resources used by the searcher.</summary>
    protected override void Dispose(bool disposing)
    {
        // A caller-supplied SearchRoot remains owned by the caller. Streaming
        // result collections own their cloned root and connection independently.
        base.Dispose(disposing);
    }
}
