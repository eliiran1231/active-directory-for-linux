using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;


/// <summary>
/// Base of the principal types (users, groups), like Microsoft's
/// <c>Principal</c>. Reads its data from the underlying
/// <see cref="DirectoryEntry"/>.
/// </summary>
public abstract class Principal : IDisposable
{
    // Values set before the object is saved, kept until there is an entry.
    private readonly Dictionary<string, object?> _pending = new(StringComparer.OrdinalIgnoreCase);

    private protected PrincipalContext ContextRef = null!;

    /// <summary>The underlying directory object, or null before it is saved.</summary>
    private protected DirectoryEntry? Entry;

    /// <summary>Sets up a found principal that wraps an existing entry.</summary>
    private protected void AttachExisting(PrincipalContext context, DirectoryEntry entry)
    {
        ContextRef = context;
        Entry = entry;
    }

    /// <summary>The context this principal belongs to.</summary>
    public PrincipalContext Context => ContextRef;

    /// <summary>The context type (Domain).</summary>
    public ContextType ContextType => ContextRef.ContextType;

    /// <summary>The distinguished name, or null before the object is saved.</summary>
    public string? DistinguishedName => Entry?.DistinguishedName;

    /// <summary>The object GUID, or null before the object is saved.</summary>
    public Guid? Guid
    {
        get
        {
            if (Entry is null)
            {
                return null;
            }

            var guid = Entry.Guid;
            return guid == System.Guid.Empty ? null : guid;
        }
    }

    /// <summary>The object name (<c>cn</c>).</summary>
    public string? Name
    {
        get => GetString("cn");
        set => SetString("cn", value);
    }

    /// <summary>The <c>sAMAccountName</c>.</summary>
    public string? SamAccountName
    {
        get => GetString("sAMAccountName");
        set => SetString("sAMAccountName", value);
    }

    /// <summary>The display name.</summary>
    public string? DisplayName
    {
        get => GetString("displayName");
        set => SetString("displayName", value);
    }

    /// <summary>The description.</summary>
    public string? Description
    {
        get => GetString("description");
        set => SetString("description", value);
    }

    /// <summary>The user principal name (user@domain).</summary>
    public string? UserPrincipalName
    {
        get => GetString("userPrincipalName");
        set => SetString("userPrincipalName", value);
    }

    /// <summary>The most specific structural class, e.g. "user" or "group".</summary>
    public string? StructuralObjectClass => Entry?.SchemaClassName;

    /// <summary>The objectClass to create this principal with, e.g. "user".</summary>
    private protected abstract string CreateObjectClass { get; }

    /// <summary>
    /// The filter piece that selects this kind of principal, e.g.
    /// <c>(objectCategory=group)</c>. Used by searches.
    /// </summary>
    internal abstract string CategoryFilter { get; }

    /// <summary>The values staged before the object is saved, by LDAP attribute.</summary>
    internal IReadOnlyDictionary<string, object?> StagedValues => _pending;

    /// <summary>
    /// The groups this principal is a direct member of. Nested groups are not
    /// followed — use <see cref="GetAuthorizationGroups"/> for that.
    /// </summary>
    public PrincipalSearchResult<Principal> GetGroups() =>
        FindGroups($"(member={IdentityFilter.Escape(RequireDistinguishedName())})");

    /// <summary>
    /// Every group this principal belongs to, directly or through nesting. Uses
    /// the AD matching rule LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941).
    /// </summary>
    public PrincipalSearchResult<Principal> GetAuthorizationGroups() =>
        FindGroups($"(member:1.2.840.113556.1.4.1941:={IdentityFilter.Escape(RequireDistinguishedName())})");

    private PrincipalSearchResult<Principal> FindGroups(string membershipFilter)
    {
        var filter = $"(&(objectCategory=group){membershipFilter})";
        var root = ContextRef.CreateDirectoryEntry(ContextRef.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter) { PageSize = 500 };
            var groups = new List<Principal>();
            using var results = searcher.FindAll();
            foreach (var result in results.Cast<SearchResult>())
            {
                groups.Add(new GroupPrincipal(ContextRef, result.GetDirectoryEntry()));
            }

            return new PrincipalSearchResult<Principal>(groups);
        }
        finally
        {
            root.Dispose();
        }
    }

    private string RequireDistinguishedName() =>
        DistinguishedName ?? throw new InvalidOperationException(
            "The principal must be saved before its groups can be read.");

    /// <summary>Runs just before a new object is created, to fill in defaults.</summary>
    private protected virtual void OnBeforeCreate()
    {
    }

    /// <summary>Runs after a successful save, for extra work like membership.</summary>
    private protected virtual void OnAfterSave()
    {
    }

    /// <summary>
    /// Writes this principal to the directory. A new principal is created under
    /// the context container (its <see cref="Name"/> becomes the CN); an
    /// existing one has its changed properties written.
    /// </summary>
    public void Save()
    {
        if (Entry is not null)
        {
            Entry.CommitChanges();
            OnAfterSave();
            return;
        }

        OnBeforeCreate();

        var cn = GetString("cn")
            ?? throw new InvalidOperationException("Name must be set before saving a new principal.");

        var parent = ContextRef.CreateDirectoryEntry(ContextRef.Container);
        try
        {
            var child = parent.Children.Add($"CN={EscapeRdnValue(cn)}", CreateObjectClass);
            foreach (var (name, value) in _pending)
            {
                // The CN is already set by the RDN above.
                if (value is null || name.Equals("cn", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                child.Properties[name].Value = value;
            }

            child.CommitChanges();
            Entry = child;
            _pending.Clear();
            OnAfterSave();
        }
        finally
        {
            parent.Dispose();
        }
    }

    /// <summary>Deletes this principal from the directory.</summary>
    public void Delete()
    {
        if (Entry is null)
        {
            throw new InvalidOperationException("Cannot delete a principal that has not been saved.");
        }

        Entry.DeleteTree();
        Entry.Dispose();
        Entry = null;
    }

    /// <summary>Escapes a value for use as an RDN (RFC 4514).</summary>
    private static string EscapeRdnValue(string value) => value
        .Replace("\\", "\\\\")
        .Replace(",", "\\,")
        .Replace("+", "\\+")
        .Replace("\"", "\\\"")
        .Replace("<", "\\<")
        .Replace(">", "\\>")
        .Replace(";", "\\;")
        .Replace("=", "\\=");

    /// <summary>The underlying <see cref="DirectoryEntry"/>.</summary>
    public object? GetUnderlyingObject() => Entry;

    /// <summary>The type behind <see cref="GetUnderlyingObject"/>.</summary>
    public Type GetUnderlyingObjectType() => typeof(DirectoryEntry);

    /// <summary>Reads a single string attribute, from the entry or a pending value.</summary>
    private protected string? GetString(string attributeName)
    {
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Value?.ToString();
        }

        return _pending.TryGetValue(attributeName, out var value) ? value?.ToString() : null;
    }

    /// <summary>Sets a single string attribute, on the entry or as a pending value.</summary>
    private protected void SetString(string attributeName, string? value)
    {
        if (Entry is not null)
        {
            if (value is null)
            {
                Entry.Properties[attributeName].Clear();
            }
            else
            {
                Entry.Properties[attributeName].Value = value;
            }
        }
        else
        {
            _pending[attributeName] = value;
        }
    }

    /// <summary>The values staged before the object is saved.</summary>
    private protected IReadOnlyDictionary<string, object?> PendingValues => _pending;

    public virtual void Dispose()
    {
        Entry?.Dispose();
        GC.SuppressFinalize(this);
    }
}
