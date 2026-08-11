using System.Collections;
using System.ComponentModel;
using System.Security.Principal;
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
    private readonly Dictionary<string, string> _advancedFilters = new(StringComparer.OrdinalIgnoreCase);

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

    /// <summary>The security identifier assigned by the directory.</summary>
    public SecurityIdentifier? Sid
    {
        get
        {
            if (Entry?.Properties["objectSid"].Value is not byte[] bytes)
            {
                return null;
            }

#pragma warning disable CA1416 // Guarded by the runtime platform check below.
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "System.Security.Principal.SecurityIdentifier is not implemented by .NET on Linux. " +
                    "Use SidValue for the portable SID string.");
            }

            return new SecurityIdentifier(bytes, 0);
#pragma warning restore CA1416
        }
    }

    /// <summary>
    /// The portable SDDL-form SID string. Unlike <see cref="Sid"/>, this works
    /// on Linux where .NET's <see cref="SecurityIdentifier"/> is a platform stub.
    /// </summary>
    public string? SidValue =>
        Entry?.Properties["objectSid"].Value is byte[] bytes
            ? SidCodec.Format(bytes)
            : null;

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
    public PrincipalSearchResult<Principal> GetGroups() => GetGroups(ContextRef);

    /// <summary>
    /// The direct groups this principal belongs to in the supplied context.
    /// </summary>
    public PrincipalSearchResult<Principal> GetGroups(PrincipalContext contextToQuery)
    {
        ArgumentNullException.ThrowIfNull(contextToQuery);
        return FindGroups(
            contextToQuery,
            $"(member={LdapFilter.EscapeValue(RequireDistinguishedName())})");
    }

    /// <summary>
    /// Every group this principal belongs to, directly or through nesting. Uses
    /// the AD matching rule LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941).
    /// </summary>
    public PrincipalSearchResult<Principal> GetAuthorizationGroups() =>
        FindGroups(
            ContextRef,
            $"(member:1.2.840.113556.1.4.1941:={LdapFilter.EscapeValue(RequireDistinguishedName())})");

    private PrincipalSearchResult<Principal> FindGroups(
        PrincipalContext contextToQuery,
        string membershipFilter)
    {
        var filter = $"(&(objectCategory=group){membershipFilter})";
        var root = contextToQuery.CreateDirectoryEntry(contextToQuery.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter) { PageSize = 500 };
            var groups = new List<Principal>();
            using var results = searcher.FindAll();
            foreach (var result in results.Cast<SearchResult>())
            {
                groups.Add(new GroupPrincipal(contextToQuery, result.GetDirectoryEntry()));
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

    /// <summary>Returns whether this principal is a direct member of a group.</summary>
    public bool IsMemberOf(GroupPrincipal group)
    {
        ArgumentNullException.ThrowIfNull(group);
        return group.Members.Contains(this);
    }

    /// <summary>
    /// Returns whether this principal is a direct member of the group selected
    /// by the supplied identity.
    /// </summary>
    public bool IsMemberOf(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identityValue);

        using var group = GroupPrincipal.FindByIdentity(context, identityType, identityValue)
            ?? throw new NoMatchingPrincipalException(
                "No group matched the supplied identity.");
        return IsMemberOf(group);
    }

    /// <summary>Finds any supported principal by a common identity value.</summary>
    public static Principal? FindByIdentity(PrincipalContext context, string identityValue) =>
        FindByIdentityWithType(context, typeof(Principal), identityValue);

    /// <summary>Finds any supported principal by a specific identity type.</summary>
    public static Principal? FindByIdentity(
        PrincipalContext context,
        IdentityType identityType,
        string identityValue) =>
        FindByIdentityWithType(context, typeof(Principal), identityType, identityValue);

    /// <summary>Typed identity lookup for custom principal subclasses.</summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    protected static Principal? FindByIdentityWithType(
        PrincipalContext context,
        Type principalType,
        string identityValue) =>
        FindByIdentityWithTypeCore(context, principalType, null, identityValue);

    /// <summary>Typed identity lookup for custom principal subclasses.</summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    protected static Principal? FindByIdentityWithType(
        PrincipalContext context,
        Type principalType,
        IdentityType identityType,
        string identityValue) =>
        FindByIdentityWithTypeCore(context, principalType, identityType, identityValue);

    private static Principal? FindByIdentityWithTypeCore(
        PrincipalContext context,
        Type principalType,
        IdentityType? identityType,
        string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principalType);
        ArgumentNullException.ThrowIfNull(identityValue);

        if (!typeof(Principal).IsAssignableFrom(principalType))
        {
            throw new ArgumentException("The requested type must derive from Principal.", nameof(principalType));
        }

        if (identityType is < IdentityType.SamAccountName or > IdentityType.Guid)
        {
            throw new InvalidEnumArgumentException(
                nameof(identityType), (int)identityType.Value, typeof(IdentityType));
        }

        var typeFilter = PrincipalTypeFilter(principalType);
        var filter = $"(&{typeFilter}{IdentityFilter.Build(identityType, identityValue)})";
        using var root = context.CreateDirectoryEntry(context.Container);
        using var searcher = new DirectorySearcher(root, filter);
        using var results = searcher.FindAll();

        Principal? match = null;
        foreach (var result in results.Cast<SearchResult>())
        {
            var entry = result.GetDirectoryEntry();
            var candidate = Materialize(context, principalType, entry);
            if (candidate is null)
            {
                entry.Dispose();
                continue;
            }

            if (match is not null)
            {
                candidate.Dispose();
                match.Dispose();
                throw new MultipleMatchesException(
                    "Multiple principal objects matched the supplied identity.");
            }

            match = candidate;
        }

        return match;
    }

    private static string PrincipalTypeFilter(Type principalType)
    {
        if (principalType == typeof(Principal))
        {
            return "(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))";
        }

        if (typeof(GroupPrincipal).IsAssignableFrom(principalType))
        {
            return "(objectCategory=group)";
        }

        if (typeof(ComputerPrincipal).IsAssignableFrom(principalType))
        {
            return "(objectCategory=computer)";
        }

        if (typeof(UserPrincipal).IsAssignableFrom(principalType))
        {
            return "(&(objectCategory=person)(objectClass=user))";
        }

        if (typeof(AuthenticablePrincipal).IsAssignableFrom(principalType))
        {
            return "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        }

        throw new NotSupportedException($"Principal type {principalType.FullName} is not supported.");
    }

    private static Principal? Materialize(
        PrincipalContext context,
        Type principalType,
        DirectoryEntry entry)
    {
        if (principalType == typeof(Principal))
        {
            return PrincipalFactory.FromEntry(context, entry);
        }

        if (principalType == typeof(UserPrincipal))
        {
            return new UserPrincipal(context, entry);
        }

        if (principalType == typeof(GroupPrincipal))
        {
            return new GroupPrincipal(context, entry);
        }

        if (principalType == typeof(ComputerPrincipal))
        {
            return new ComputerPrincipal(context, entry);
        }

        if (Activator.CreateInstance(principalType, context) is not Principal principal)
        {
            throw new NotSupportedException(
                $"Principal type {principalType.FullName} must have a public constructor that accepts PrincipalContext.");
        }

        principal.AttachExisting(context, entry);
        return principal;
    }

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

    /// <summary>
    /// Saves a new principal in, or moves an existing principal to, another
    /// domain context.
    /// </summary>
    public void Save(PrincipalContext context)
    {
        if (context is null)
        {
            throw new InvalidOperationException("The target context cannot be null.");
        }

        if (ReferenceEquals(context, ContextRef))
        {
            Save();
            return;
        }

        if (Entry is null)
        {
            ContextRef = context;
            Save();
            return;
        }

        if (!string.Equals(context.Name, ContextRef.Name, StringComparison.OrdinalIgnoreCase)
            || context.Port != ContextRef.Port)
        {
            throw new PlatformNotSupportedException(
                "LDAP cannot move an existing principal between different directory servers.");
        }

        Entry.CommitChanges();
        var currentDn = Entry.DistinguishedName;
        var currentParent = ParentDistinguishedName(currentDn);
        if (!string.Equals(currentParent, context.Container, StringComparison.OrdinalIgnoreCase))
        {
            using var target = context.CreateDirectoryEntry(context.Container);
            Entry.MoveTo(target);
            currentDn = Entry.DistinguishedName;
        }

        Entry.Dispose();
        Entry = context.CreateDirectoryEntry(currentDn);
        ContextRef = context;
        OnAfterSave();
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

    private static string? ParentDistinguishedName(string distinguishedName)
    {
        for (var index = 0; index < distinguishedName.Length; index++)
        {
            if (distinguishedName[index] == ',' && (index == 0 || distinguishedName[index - 1] != '\\'))
            {
                return distinguishedName[(index + 1)..];
            }
        }

        return null;
    }

    /// <summary>The underlying <see cref="DirectoryEntry"/>.</summary>
    public object? GetUnderlyingObject() => Entry;

    /// <summary>The type behind <see cref="GetUnderlyingObject"/>.</summary>
    public Type GetUnderlyingObjectType() => typeof(DirectoryEntry);

    /// <summary>Reads an arbitrary directory attribute for an extension class.</summary>
    protected object?[] ExtensionGet(string attribute)
    {
        if (attribute is null)
        {
            throw new ArgumentException("The attribute cannot be null.", nameof(attribute));
        }

        if (Entry is not null)
        {
            return Entry.Properties[attribute].Cast<object?>().ToArray();
        }

        if (!_pending.TryGetValue(attribute, out var value))
        {
            return Array.Empty<object?>();
        }

        return value switch
        {
            object?[] values => values.ToArray(),
            null => new object?[] { null },
            _ => new object?[] { value },
        };
    }

    /// <summary>Stages an arbitrary directory attribute for an extension class.</summary>
    protected void ExtensionSet(string attribute, object? value)
    {
        if (attribute is null)
        {
            throw new ArgumentException("The attribute cannot be null.", nameof(attribute));
        }

        ValidateExtensionValue(value);
        var values = value switch
        {
            object?[] array => array.ToArray(),
            byte[] bytes => new object?[] { bytes },
            ICollection collection => collection.Cast<object?>().ToArray(),
            _ => new object?[] { value },
        };

        if (Entry is not null)
        {
            if (values.Length == 1 && values[0] is null)
            {
                Entry.Properties[attribute].Clear();
            }
            else
            {
                Entry.Properties[attribute].Value = values;
            }
        }
        else
        {
            _pending[attribute] = value is null ? null : values;
        }
    }

    private static void ValidateExtensionValue(object? value)
    {
        if (value is byte[] bytes)
        {
            if (bytes.Length == 0)
            {
                throw new ArgumentException("An extension collection cannot be empty.", nameof(value));
            }

            return;
        }

        if (value is not ICollection collection)
        {
            return;
        }

        if (collection.Count == 0)
        {
            throw new ArgumentException("An extension collection cannot be empty.", nameof(value));
        }

        foreach (var item in collection)
        {
            if (item is ICollection)
            {
                throw new ArgumentException("Nested extension collections are not supported.", nameof(value));
            }
        }
    }

    /// <summary>Returns true when both objects represent the same stored principal.</summary>
    public override bool Equals(object? obj)
    {
        if (obj is not Principal other)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        var guid = Guid;
        return guid is not null && other.Guid is not null && guid == other.Guid;
    }

    /// <summary>Matches Microsoft's instance-based hash behavior.</summary>
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Reads a single string attribute, from the entry or a pending value.</summary>
    private protected string? GetString(string attributeName)
    {
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Value?.ToString();
        }

        return _pending.TryGetValue(attributeName, out var value) ? value?.ToString() : null;
    }

    private protected IEnumerable<string> GetValues(string attributeName)
    {
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Cast<object>().Select(value => value.ToString()!).ToArray();
        }

        return _pending.TryGetValue(attributeName, out var value) && value is IEnumerable<object> many
            ? many.Select(item => item.ToString()!).ToArray()
            : Array.Empty<string>();
    }

    private protected void SetValues<T>(string attributeName, IReadOnlyList<T> values)
    {
        var array = values.Cast<object>().ToArray();
        if (Entry is not null)
        {
            Entry.Properties[attributeName].Value = array;
        }
        else
        {
            _pending[attributeName] = array;
        }
    }

    internal void SetAdvancedFilter(string attribute, string value, MatchType match) =>
        _advancedFilters[attribute] = AdvancedFilters.ToLdapCondition(attribute, value, match);

    internal IEnumerable<string> AdvancedFilterConditions => _advancedFilters.Values;

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
