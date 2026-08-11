using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Finds principals that look like a filled-in example, like Microsoft's
/// <c>PrincipalSearcher</c>:
///
/// <code>
/// var searcher = new PrincipalSearcher(new UserPrincipal(context) { SamAccountName = "jeff*" });
/// var match = searcher.FindOne();
/// </code>
///
/// Every property you set on the example must match. A <c>*</c> in a value works
/// as a wildcard.
/// </summary>
public class PrincipalSearcher : IDisposable
{
    private PrincipalContext? _context;
    private Principal? _queryFilter;
    private DirectorySearcher? _underlyingSearcher;
    private PrincipalContext? _underlyingContext;
    private DirectoryEntry? _searchRoot;
    private bool _disposed;

    /// <summary>Creates a searcher with no example yet.</summary>
    public PrincipalSearcher()
    {
    }

    /// <summary>Creates a searcher for principals matching the example.</summary>
    public PrincipalSearcher(Principal queryFilter)
    {
        QueryFilter = queryFilter ?? throw new ArgumentException(null, nameof(queryFilter));
    }

    /// <summary>The example principal whose set properties must all match.</summary>
    public Principal? QueryFilter
    {
        get => _queryFilter;
        set
        {
            ThrowIfDisposed();
            if (value is null)
            {
                throw new ArgumentNullException(nameof(QueryFilter));
            }

            if (value.IsPersisted)
            {
                throw new ArgumentException(
                    "A persisted principal cannot be used as a query filter.",
                    nameof(QueryFilter));
            }

            var previousContext = _context;
            _queryFilter = value;
            _context = value.Context;
            if (!ReferenceEquals(previousContext, _context))
            {
                ResetUnderlyingSearcher();
            }
        }
    }

    /// <summary>The context taken from the current query filter.</summary>
    public PrincipalContext? Context
    {
        get
        {
            ThrowIfDisposed();
            return _context;
        }
    }

    /// <summary>Returns the first match, or null.</summary>
    public Principal? FindOne()
    {
        var searcher = PrepareUnderlyingSearcher();
        var originalSizeLimit = searcher.SizeLimit;
        try
        {
            searcher.SizeLimit = 1;
            var result = searcher.FindOne();
            return result is null
                ? null
                : PrincipalFactory.FromEntry(Context!, result.GetDirectoryEntry());
        }
        finally
        {
            searcher.SizeLimit = originalSizeLimit;
        }
    }

    /// <summary>Returns every match.</summary>
    public PrincipalSearchResult<Principal> FindAll()
    {
        var searcher = PrepareUnderlyingSearcher();
        var found = new List<Principal>();
        using var results = searcher.FindAll();
        foreach (var result in results.Cast<SearchResult>())
        {
            var entry = result.GetDirectoryEntry();
            var principal = PrincipalFactory.FromEntry(Context!, entry);
            if (principal is null)
            {
                entry.Dispose();
                continue;
            }

            found.Add(principal);
        }

        return new PrincipalSearchResult<Principal>(found);
    }

    /// <summary>
    /// Returns the LDAP searcher used for this query. Changes made to the returned
    /// object are retained and used by <see cref="FindOne"/> and <see cref="FindAll"/>.
    /// </summary>
    public object GetUnderlyingSearcher() => PrepareUnderlyingSearcher();

    /// <summary>Returns the type produced by <see cref="GetUnderlyingSearcher"/>.</summary>
    public Type GetUnderlyingSearcherType()
    {
        ThrowIfDisposed();
        if (_queryFilter is null)
        {
            throw new InvalidOperationException("QueryFilter must be set before searching.");
        }

        return typeof(DirectorySearcher);
    }

    /// <summary>The LDAP filter this searcher will send. Useful for debugging.</summary>
    public string GetLdapFilter() => Build().Filter;

    private DirectorySearcher PrepareUnderlyingSearcher()
    {
        ThrowIfDisposed();
        var (context, filter) = Build();
        if (_underlyingSearcher is null || !ReferenceEquals(_underlyingContext, context))
        {
            ResetUnderlyingSearcher();
            _searchRoot = context.CreateDirectoryEntry(context.Container);
            _underlyingSearcher = new DirectorySearcher(_searchRoot)
            {
                PageSize = 256,
                ServerTimeLimit = TimeSpan.FromSeconds(30),
            };
            _underlyingContext = context;
        }

        // Match Microsoft's PushFilterToNativeSearcher behavior: refresh the QBE
        // filter for each accessor/query while preserving caller changes to the
        // other DirectorySearcher properties.
        _underlyingSearcher.Filter = filter;
        return _underlyingSearcher;
    }

    private (PrincipalContext Context, string Filter) Build()
    {
        var example = QueryFilter
            ?? throw new InvalidOperationException("QueryFilter must be set before searching.");

        if (example.IsPersisted)
        {
            throw new InvalidOperationException(
                "A persisted principal cannot be used as a query filter.");
        }

        var context = _context
            ?? throw new InvalidOperationException("No context: set Context or give the example one.");

        var conditions = string.Concat(
            example.StagedValues
                .Where(pair => pair.Value is not null)
                .Select(pair => $"({pair.Key}={EscapeKeepingWildcards(pair.Value!.ToString()!)})"));

        conditions += string.Concat(example.AdvancedFilterConditions);

        return (context, $"(&{example.CategoryFilter}{conditions})");
    }

    /// <summary>
    /// Escapes a value for a filter but leaves <c>*</c> alone, so it still works
    /// as a wildcard, which is what query-by-example expects.
    /// </summary>
    private static string EscapeKeepingWildcards(string value) => value
        .Replace("\\", "\\5c")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");

    private void ResetUnderlyingSearcher()
    {
        _underlyingSearcher?.Dispose();
        _searchRoot?.Dispose();
        _underlyingSearcher = null;
        _underlyingContext = null;
        _searchRoot = null;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public virtual void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ResetUnderlyingSearcher();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
