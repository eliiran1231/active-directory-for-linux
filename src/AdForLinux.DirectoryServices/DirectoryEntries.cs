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
    private readonly DirectoryEntry.BindingAuthority _authority;
    internal Action<DirectoryEntry>? BeforeChildLookup { get; set; }
    internal Action<DirectorySearcher>? SearcherCreated { get; set; }

    internal DirectoryEntries(DirectoryEntry parent)
    {
        _parent = parent;
        _authority = parent.CaptureBindingAuthority();
    }

    /// <summary>
    /// Makes a new, unsaved child object, e.g. <c>Add("CN=Jeff", "user")</c>.
    /// Set its properties, then call <c>CommitChanges</c> to create it.
    /// </summary>
    public DirectoryEntry Add(string name, string schemaClassName)
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        return _authority.Checked(() => DirectoryEntry.NewChild(_parent, name, schemaClassName));
    }

    /// <summary>
    /// Gets the schema classes included when enumerating the children. An empty
    /// collection includes children of every class.
    /// </summary>
    public SchemaNameCollection SchemaFilter => _authority.Checked(() => new SchemaNameCollection(_parent, _authority));

    /// <summary>Finds a child by relative distinguished name.</summary>
    public DirectoryEntry Find(string name) => Find(name, null);

    /// <summary>Finds a child by relative distinguished name and optional schema class.</summary>
    public DirectoryEntry Find(string name, string? schemaClassName)
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var child = _authority.Checked(() => _parent.CreateEntryForDn($"{name},{_parent.DistinguishedName}"));
        try
        {
            BeforeChildLookup?.Invoke(child);
            _authority.Validate();
            child.RefreshCache();
            if (!string.IsNullOrEmpty(schemaClassName)
                && !string.Equals(child.SchemaClassName, schemaClassName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Child '{name}' does not have schema class '{schemaClassName}'.");
            }

            _authority.Validate();
            return child;
        }
        catch
        {
            child.Dispose();
            throw;
        }
    }

    /// <summary>Deletes a child object without recursively deleting its descendants.</summary>
    public void Remove(DirectoryEntry entry)
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        // Microsoft asks this collection's parent container to delete the
        // entry by schema class and relative name. Reading SchemaClassName
        // preserves the observable bind/error behavior even though LDAP's
        // DeleteRequest does not carry the schema class.
        using var sameParent = ReferenceEquals(entry, _parent) ? _parent.CopyBinding(_authority) : null;
        var target = sameParent ?? entry;
        _ = target.SchemaClassName;
        _parent.DeleteChild(target.Name, _authority);
    }

    public IEnumerator GetEnumerator()
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        return new ChildEnumerator(this);
    }

    IEnumerator<DirectoryEntry> IEnumerable<DirectoryEntry>.GetEnumerator()
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        return new ChildEnumerator(this);
    }

    private IEnumerable<DirectoryEntry> Enumerate()
    {
        _authority.Validate();
        _parent.ThrowIfDisposed();
        using var searcher = _authority.Checked(() => new DirectorySearcher(_parent, BuildSchemaFilter())
        {
            SearchScope = SearchScope.OneLevel,
            PageSize = _parent.Options.PageSize,
            ReferralChasing = _parent.Options.Referral,
        });

        SearcherCreated?.Invoke(searcher);
        using var results = searcher.FindAll();
        foreach (var result in results.Cast<SearchResult>())
        {
            _authority.Validate();
            yield return result.GetDirectoryEntry();
        }
    }

    private sealed class ChildEnumerator(DirectoryEntries owner) : IEnumerator<DirectoryEntry>
    {
        private IEnumerator<DirectoryEntry>? _iterator;
        private bool _positioned;

        public DirectoryEntry Current => _positioned
            ? _iterator!.Current
            : throw new InvalidOperationException("The enumerator is not positioned on a child.");
        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            owner._authority.Validate();
            _iterator ??= owner.Enumerate().GetEnumerator();
            return _positioned = _iterator.MoveNext();
        }

        public void Reset()
        {
            _iterator?.Dispose();
            _iterator = null;
            _positioned = false;
        }

        public void Dispose() => Reset();
    }

    private string BuildSchemaFilter()
    {
        var clauses = SchemaFilter.OfType<string>()
            .Select(name => $"(objectClass={EscapeFilterValue(name)})")
            .ToArray();
        if (clauses.Length == 0)
        {
            return "(objectClass=*)";
        }

        return $"(|{string.Concat(clauses)})";
    }

    private static string EscapeFilterValue(string value) => value
        .Replace("\\", "\\5c", StringComparison.Ordinal)
        .Replace("*", "\\2a", StringComparison.Ordinal)
        .Replace("(", "\\28", StringComparison.Ordinal)
        .Replace(")", "\\29", StringComparison.Ordinal)
        .Replace("\0", "\\00", StringComparison.Ordinal);
}
