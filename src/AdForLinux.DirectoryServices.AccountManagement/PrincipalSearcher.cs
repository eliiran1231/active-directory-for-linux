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
    /// <summary>Creates a searcher with no example yet.</summary>
    public PrincipalSearcher()
    {
    }

    /// <summary>Creates a searcher for principals matching the example.</summary>
    public PrincipalSearcher(Principal queryFilter)
    {
        QueryFilter = queryFilter;
    }

    /// <summary>The example principal whose set properties must all match.</summary>
    public Principal? QueryFilter { get; set; }

    /// <summary>The context searched. Taken from the example if not set.</summary>
    public PrincipalContext? Context
    {
        get => _context ?? QueryFilter?.Context;
        set => _context = value;
    }

    private PrincipalContext? _context;

    /// <summary>Returns the first match, or null.</summary>
    public Principal? FindOne()
    {
        var (context, filter) = Build();
        var root = context.CreateDirectoryEntry(context.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter);
            var result = searcher.FindOne();
            return result is null ? null : PrincipalFactory.FromEntry(context, result.GetDirectoryEntry());
        }
        finally
        {
            root.Dispose();
        }
    }

    /// <summary>Returns every match.</summary>
    public PrincipalSearchResult<Principal> FindAll()
    {
        var (context, filter) = Build();
        var root = context.CreateDirectoryEntry(context.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter) { PageSize = 500 };
            var found = new List<Principal>();
            using var results = searcher.FindAll();
            foreach (var result in results.Cast<SearchResult>())
            {
                var entry = result.GetDirectoryEntry();
                var principal = PrincipalFactory.FromEntry(context, entry);
                if (principal is null)
                {
                    entry.Dispose();
                    continue;
                }

                found.Add(principal);
            }

            return new PrincipalSearchResult<Principal>(found);
        }
        finally
        {
            root.Dispose();
        }
    }

    /// <summary>The LDAP filter this searcher will send. Useful for debugging.</summary>
    public string GetLdapFilter() => Build().Filter;

    private (PrincipalContext Context, string Filter) Build()
    {
        var example = QueryFilter
            ?? throw new InvalidOperationException("QueryFilter must be set before searching.");

        var context = Context
            ?? throw new InvalidOperationException("No context: set Context or give the example one.");

        var conditions = string.Concat(
            example.StagedValues
                .Where(pair => pair.Value is not null)
                .Select(pair => $"({pair.Key}={EscapeKeepingWildcards(pair.Value!.ToString()!)})"));

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

    public void Dispose() => GC.SuppressFinalize(this);
}
