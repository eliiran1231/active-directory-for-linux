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
    private DirectoryEntry? _searchRoot;
    private bool _disposed;
    private readonly int _defaultPageSize;

    /// <summary>Creates a searcher with no example yet.</summary>
    public PrincipalSearcher()
    {
    }

    /// <summary>Creates a searcher for principals matching the example.</summary>
    public PrincipalSearcher(Principal queryFilter)
    {
        QueryFilter = queryFilter ?? throw new ArgumentException(null, nameof(queryFilter));
        _defaultPageSize = 256;
    }

    /// <summary>The example principal whose set properties must all match.</summary>
    public Principal? QueryFilter
    {
        get
        {
            ThrowIfDisposed();
            return _queryFilter;
        }
        set
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(QueryFilter));
            }

            ThrowIfDisposed();

            if (value.Context is null)
            {
                throw new ArgumentException("The query filter must have a context.");
            }

            if (value.IsPersisted)
            {
                throw new ArgumentException(
                    "A persisted principal cannot be used as a query filter.",
                    nameof(QueryFilter));
            }

            _queryFilter = value;
            _context = value.Context;
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
    public Principal? FindOne() => AccountManagementExceptionTranslator.Execute(FindOneCore);

    private Principal? FindOneCore()
    {
        var searcher = PrepareUnderlyingSearcher();
        var originalSizeLimit = searcher.SizeLimit;
        searcher.SizeLimit = 1;
        var result = searcher.FindOne();
        searcher.SizeLimit = originalSizeLimit;
        return result is null
            ? null
            : Principal.Materialize(Context!, QueryFilter!.GetType(), result.GetDirectoryEntry());
    }

    /// <summary>Returns every match.</summary>
    public PrincipalSearchResult<Principal> FindAll() =>
        AccountManagementExceptionTranslator.Execute(FindAllCore);

    private PrincipalSearchResult<Principal> FindAllCore()
    {
        var searcher = PrepareUnderlyingSearcher();
        using var results = searcher.FindAll();
        var rows = results.Cast<SearchResult>().ToArray();
        var context = Context!;
        var type = QueryFilter!.GetType();
        return new PrincipalSearchResult<Principal>(rows.Length, index =>
            Principal.Materialize(context, type, rows[index].GetDirectoryEntry())!);
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
        if (_underlyingSearcher is null)
        {
            _searchRoot = context.SearchRoot;
            _underlyingSearcher = new DirectorySearcher(_searchRoot)
            {
                PageSize = _defaultPageSize,
                ServerTimeLimit = TimeSpan.FromSeconds(30),
            };
        }

        // Match Microsoft's PushFilterToNativeSearcher behavior: refresh the QBE
        // filter for each accessor/query while preserving caller changes to the
        // other DirectorySearcher properties.
        _underlyingSearcher.Filter = filter;
        _underlyingSearcher.PropertiesToLoad.AddRange(PrincipalSearchProjection.For(_queryFilter!.GetType()).ToArray());
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

        if (example is GroupPrincipal { HasReferentialPropertiesSet: true })
        {
            throw new InvalidOperationException(
                "Referential properties cannot be used in a query filter.");
        }

        var context = _context
            ?? throw new InvalidOperationException("No context: set Context or give the example one.");

        var conditions = PrincipalQueryFilterTranslator.Translate(example.QueryFilters);

        conditions += string.Concat(example.AdvancedFilterConditions);

        return (context, $"(&{CategoryFilterFor(example)}{conditions})");
    }

    private static string CategoryFilterFor(Principal example)
    {
        var type = example.GetType();
        if (type == typeof(UserPrincipal)
            || type == typeof(GroupPrincipal)
            || type == typeof(ComputerPrincipal))
        {
            return example.CategoryFilter;
        }

        var objectClass = PrincipalExtensionMetadata.GetDeclaredObjectClass(type);
        return objectClass is null
            ? example.CategoryFilter
            : $"(objectClass={LdapFilter.EscapeValue(objectClass)})";
    }

    private void ResetUnderlyingSearcher()
    {
        _underlyingSearcher?.Dispose();
        _underlyingSearcher = null;
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
