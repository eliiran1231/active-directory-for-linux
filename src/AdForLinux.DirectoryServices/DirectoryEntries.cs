using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The children of a <see cref="DirectoryEntry"/>, like Microsoft's
/// <c>DirectoryEntries</c>. Use <see cref="Add"/> to create a child and
/// <see cref="Remove"/> to delete one.
/// </summary>
public class DirectoryEntries : IEnumerable<DirectoryEntry>
{
    private readonly DirectoryEntry _parent;
    private readonly SchemaNameCollection _schemaFilter = new();

    internal DirectoryEntries(DirectoryEntry parent)
    {
        _parent = parent;
    }

    /// <summary>
    /// Makes a new, unsaved child object, e.g. <c>Add("CN=Jeff", "user")</c>.
    /// Set its properties, then call <c>CommitChanges</c> to create it.
    /// </summary>
    public DirectoryEntry Add(string name, string schemaClassName)
    {
        _parent.ThrowIfDisposed();
        return DirectoryEntry.NewChild(_parent, name, schemaClassName);
    }

    /// <summary>
    /// Gets the schema classes included when enumerating the children. An empty
    /// collection includes children of every class.
    /// </summary>
    public SchemaNameCollection SchemaFilter => _schemaFilter;

    /// <summary>Finds a child by relative distinguished name.</summary>
    public DirectoryEntry Find(string name) => Find(name, null);

    /// <summary>Finds a child by relative distinguished name and optional schema class.</summary>
    public DirectoryEntry Find(string name, string? schemaClassName)
    {
        _parent.ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var child = _parent.CreateEntryForDn($"{name},{_parent.DistinguishedName}");
        try
        {
            child.RefreshCache();
            if (!string.IsNullOrEmpty(schemaClassName)
                && !string.Equals(child.SchemaClassName, schemaClassName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Child '{name}' does not have schema class '{schemaClassName}'.");
            }

            return child;
        }
        catch
        {
            child.Dispose();
            throw;
        }
    }

    /// <summary>Deletes a child object without recursively deleting its descendants.</summary>
    public void Remove(DirectoryEntry child)
    {
        _parent.ThrowIfDisposed();
        // Microsoft asks this collection's parent container to delete the
        // entry by schema class and relative name. Reading SchemaClassName
        // preserves the observable bind/error behavior even though LDAP's
        // DeleteRequest does not carry the schema class.
        _ = child.SchemaClassName;
        _parent.DeleteChild(child.Name);
    }

    public IEnumerator GetEnumerator()
    {
        _parent.ThrowIfDisposed();
        return Enumerate().GetEnumerator();
    }

    IEnumerator<DirectoryEntry> IEnumerable<DirectoryEntry>.GetEnumerator()
    {
        _parent.ThrowIfDisposed();
        return Enumerate().GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    private IEnumerable<DirectoryEntry> Enumerate()
    {
        _parent.ThrowIfDisposed();
        using var searcher = new DirectorySearcher(_parent, BuildSchemaFilter())
        {
            SearchScope = SearchScope.OneLevel,
            PageSize = _parent.Options.PageSize,
            ReferralChasing = _parent.Options.Referral,
        };

        using var results = searcher.FindAll();
        foreach (var result in results.Cast<SearchResult>())
        {
            yield return result.GetDirectoryEntry();
        }
    }

    private string BuildSchemaFilter()
    {
        if (_schemaFilter.Count == 0)
        {
            return "(objectClass=*)";
        }

        var clauses = _schemaFilter.Cast<string>()
            .Select(name => $"(objectClass={EscapeFilterValue(name)})");
        return $"(|{string.Concat(clauses)})";
    }

    private static string EscapeFilterValue(string value) => value
        .Replace("\\", "\\5c", StringComparison.Ordinal)
        .Replace("*", "\\2a", StringComparison.Ordinal)
        .Replace("(", "\\28", StringComparison.Ordinal)
        .Replace(")", "\\29", StringComparison.Ordinal)
        .Replace("\0", "\\00", StringComparison.Ordinal);
}
