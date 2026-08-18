using System.Collections;
using System.ComponentModel;
using System.Security.Principal;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;

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
    private readonly Dictionary<string, object?[]> _extensionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _advancedFilters = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PrincipalQueryFilter> _queryFilters = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;
    private bool _deleted;

    private protected PrincipalContext ContextRef = null!;

    /// <summary>The underlying directory object, or null before it is saved.</summary>
    private protected DirectoryEntry? Entry;

    /// <summary>Whether this principal currently wraps a directory object.</summary>
    internal bool IsPersisted => Entry is not null;

    /// <summary>Sets up a found principal that wraps an existing entry.</summary>
    private protected void AttachExisting(PrincipalContext context, DirectoryEntry entry)
    {
        ContextRef = context;
        Entry = entry;
    }

    /// <summary>The context this principal belongs to.</summary>
    public PrincipalContext Context
    {
        get
        {
            CheckDisposedOrDeleted();
            return ContextRef;
        }
    }

    /// <summary>
    /// Low-level context access for custom principal implementations.
    /// </summary>
    [Browsable(false)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    protected internal PrincipalContext ContextRaw
    {
        get => ContextRef;
        set
        {
            value?.CheckDisposed();
            ContextRef = value!;
        }
    }

    /// <summary>The context type (Domain).</summary>
    public ContextType ContextType
    {
        get
        {
            CheckDisposedOrDeleted();
            return ContextRef.ContextType;
        }
    }

    /// <summary>The distinguished name, or null before the object is saved.</summary>
    public string? DistinguishedName
    {
        get
        {
            CheckDisposedOrDeleted();
            return Entry?.DistinguishedName;
        }
    }

    /// <summary>The object GUID, or null before the object is saved.</summary>
    public Guid? Guid
    {
        get
        {
            CheckDisposedOrDeleted();
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
            CheckDisposedOrDeleted();
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
    public string? SidValue
    {
        get
        {
            CheckDisposedOrDeleted();
            return Entry?.Properties["objectSid"].Value is byte[] bytes
                ? SidCodec.Format(bytes)
                : null;
        }
    }

    /// <summary>The object name (<c>cn</c>).</summary>
    public string? Name
    {
        get
        {
            // Microsoft consults the context type before its normal principal
            // guard because machine contexts map Name to SamAccountName.
            _ = ContextRef.ContextType;
            CheckDisposedOrDeleted();
            if (Entry is not null)
            {
                return Entry.Properties["name"].Value?.ToString();
            }

            return _pending.TryGetValue("cn", out var value) ? value?.ToString() : null;
        }
        set
        {
            _ = ContextRef.ContextType;
            SetString("cn", value);
        }
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
    public string? StructuralObjectClass
    {
        get
        {
            CheckDisposedOrDeleted();
            return Entry?.SchemaClassName;
        }
    }

    public override string? ToString() => Name;

    /// <summary>The objectClass to create this principal with, e.g. "user".</summary>
    private protected virtual string CreateObjectClass =>
        PrincipalExtensionMetadata.GetDeclaredObjectClass(GetType())
        ?? throw new InvalidOperationException(
            $"Custom principal type {GetType().FullName} must declare " +
            $"{nameof(DirectoryObjectClassAttribute)}.");

    /// <summary>
    /// The filter piece that selects this kind of principal, e.g.
    /// <c>(objectCategory=group)</c>. Used by searches.
    /// </summary>
    internal virtual string CategoryFilter
    {
        get
        {
            var objectClass = PrincipalExtensionMetadata.GetDeclaredObjectClass(GetType())
                ?? throw new InvalidOperationException(
                    $"Custom principal type {GetType().FullName} must declare " +
                    $"{nameof(DirectoryObjectClassAttribute)}.");
            return $"(objectClass={LdapFilter.EscapeValue(objectClass)})";
        }
    }

    /// <summary>The values staged before the object is saved, by LDAP attribute.</summary>
    internal IReadOnlyDictionary<string, object?> StagedValues => _pending;

    internal virtual IEnumerable<PrincipalQueryFilter> QueryFilters => _queryFilters.Values;

    /// <summary>
    /// The groups this principal is a direct member of. Nested groups are not
    /// followed — use <see cref="UserPrincipal.GetAuthorizationGroups"/> for that.
    /// </summary>
    public PrincipalSearchResult<Principal> GetGroups()
    {
        CheckDisposedOrDeleted();
        return Entry is null
            ? new PrincipalSearchResult<Principal>(Array.Empty<Principal>())
            : GetGroups(ContextRef);
    }

    /// <summary>
    /// The direct groups this principal belongs to in the supplied context.
    /// </summary>
    public PrincipalSearchResult<Principal> GetGroups(PrincipalContext contextToQuery)
    {
        ArgumentNullException.ThrowIfNull(contextToQuery);
        CheckDisposedOrDeleted();
        var memberFilter = $"(member={LdapFilter.EscapeValue(RequireDistinguishedName())})";
        var primaryGroupSid = TryGetPrimaryGroupSid();
        var membershipFilter = primaryGroupSid is null
            ? memberFilter
            : $"(|{memberFilter}(objectSid={LdapFilter.EscapeBytes(primaryGroupSid)}))";
        return FindGroups(
            contextToQuery,
            membershipFilter);
    }

    private protected PrincipalSearchResult<Principal> GetAuthorizationGroupsCore()
    {
        CheckDisposedOrDeleted();
        var distinguishedName = RequireDistinguishedName();
        var root = ContextRef.CreateDirectoryEntry(distinguishedName);
        try
        {
            using var tokenSearcher = new DirectorySearcher(
                root,
                "(objectClass=*)",
                new[] { "tokenGroups" },
                SearchScope.Base);
            var tokenResult = tokenSearcher.FindOne();
            var tokenSids = tokenResult?.Properties["tokenGroups"]
                .Cast<object>()
                .OfType<byte[]>()
                .ToList() ?? new List<byte[]>();

            if (tokenSids.Count == 0)
            {
                // Some LDAP servers do not expose tokenGroups. Keep the normal
                // transitive membership behavior, but explicitly include the
                // principal's primary group so it is never silently omitted.
                var memberFilter =
                    $"(member:1.2.840.113556.1.4.1941:={LdapFilter.EscapeValue(distinguishedName)})";
                var primaryGroupSid = TryGetPrimaryGroupSid();
                return FindGroups(
                    ContextRef,
                    primaryGroupSid is null
                        ? memberFilter
                        : $"(|{memberFilter}(objectSid={LdapFilter.EscapeBytes(primaryGroupSid)}))");
            }

            var sidFilter = string.Concat(tokenSids.Select(
                sid => $"(objectSid={LdapFilter.EscapeBytes(sid)})"));
            return FindGroups(ContextRef, $"(|{sidFilter})");
        }
        finally
        {
            root.Dispose();
        }
    }

    private PrincipalSearchResult<Principal> FindGroups(
        PrincipalContext contextToQuery,
        string membershipFilter)
    {
        var filter = $"(&(objectCategory=group){membershipFilter})";
        var root = contextToQuery.CreateDirectoryEntry(contextToQuery.DefaultNamingContext);
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
        CheckDisposedOrDeleted();
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
        CheckDisposedOrDeleted();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(identityValue);

        using var group = GroupPrincipal.FindByIdentity(context, identityType, identityValue)
            ?? throw new NoMatchingPrincipalException(
                "No group matched the supplied identity.");
        return IsMemberOf(group);
    }

    internal bool IsPrimaryGroup(GroupPrincipal group)
    {
        var primaryGroupSid = TryGetPrimaryGroupSid();
        var groupSid = group.RequireEntry().Properties["objectSid"].Value as byte[];
        return primaryGroupSid is not null
            && groupSid is not null
            && primaryGroupSid.AsSpan().SequenceEqual(groupSid);
    }

    private byte[]? TryGetPrimaryGroupSid()
    {
        if (Entry?.Properties["objectSid"].Value is not byte[] objectSid)
        {
            return null;
        }

        var rawRid = Entry.Properties["primaryGroupID"].Value;
        if (!uint.TryParse(
                Convert.ToString(rawRid, System.Globalization.CultureInfo.InvariantCulture),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var rid))
        {
            return null;
        }

        return SidCodec.ReplaceRid(objectSid, rid);
    }

    internal uint? GetPrimaryGroupRid()
    {
        var rawRid = Entry?.Properties["primaryGroupID"].Value;
        return uint.TryParse(
            Convert.ToString(rawRid, System.Globalization.CultureInfo.InvariantCulture),
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out var rid)
            ? rid
            : null;
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

        var identityFilters = identityType is null
            ? IdentityFilter.BuildValueOnlyCandidates(identityValue)
            : new[] { IdentityFilter.Build(identityType, identityValue) };
        foreach (var identityFilter in identityFilters)
        {
            var match = FindByIdentityFilter(context, principalType, identityFilter);
            if (match is not null)
            {
                return match;
            }
        }

        return null;
    }

    private static Principal? FindByIdentityFilter(
        PrincipalContext context,
        Type principalType,
        string identityFilter)
    {
        var filter = $"(&{PrincipalTypeFilter(principalType)}{identityFilter})";
        using var root = context.CreateDirectoryEntry(context.Container);
        using var searcher = new DirectorySearcher(root, filter) { SizeLimit = 2 };
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

        if (principalType == typeof(GroupPrincipal))
        {
            return "(objectCategory=group)";
        }

        if (principalType == typeof(ComputerPrincipal))
        {
            return "(objectCategory=computer)";
        }

        if (principalType == typeof(UserPrincipal))
        {
            return "(&(objectCategory=person)(objectClass=user))";
        }

        if (principalType == typeof(AuthenticablePrincipal))
        {
            return "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        }

        var objectClass = PrincipalExtensionMetadata.GetDeclaredObjectClass(principalType);
        if (objectClass is not null)
        {
            return $"(objectClass={LdapFilter.EscapeValue(objectClass)})";
        }

        throw new NotSupportedException($"Principal type {principalType.FullName} is not supported.");
    }

    internal static Principal? Materialize(
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

    /// <summary>Runs immediately before pending property changes are committed.</summary>
    private protected virtual void OnBeforeSave()
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
        CheckDisposedOrDeleted();
        if (Entry is not null)
        {
            OnBeforeSave();
            ApplyExtensionChanges(Entry);
            Entry.CommitChanges();
            _extensionCache.Clear();
            OnAfterSave();
            return;
        }

        OnBeforeCreate();
        OnBeforeSave();

        var cn = GetString("cn")
            ?? throw new InvalidOperationException("Name must be set before saving a new principal.");

        var principalType = GetType();
        var objectClass = PrincipalExtensionMetadata.GetObjectClassForCreation(
            principalType, CreateObjectClass);
        var rdnPrefix = PrincipalExtensionMetadata.GetRdnPrefixForCreation(principalType);
        var writeBaseCn = !rdnPrefix.Equals("CN", StringComparison.OrdinalIgnoreCase)
            && (typeof(UserPrincipal).IsAssignableFrom(principalType)
                || typeof(GroupPrincipal).IsAssignableFrom(principalType)
                || typeof(ComputerPrincipal).IsAssignableFrom(principalType));

        var parent = ContextRef.CreateDirectoryEntry(ContextRef.Container);
        try
        {
            var child = parent.Children.Add(
                $"{rdnPrefix}={EscapeRdnValue(cn)}", objectClass);
            foreach (var (name, value) in _pending)
            {
                // The RDN attribute is already set by Children.Add. When a
                // custom type uses a different RDN, retain the base CN value as
                // Microsoft does for UserPrincipal/GroupPrincipal subclasses.
                if (value is null
                    || name.Equals(rdnPrefix, StringComparison.OrdinalIgnoreCase)
                    || (name.Equals("cn", StringComparison.OrdinalIgnoreCase) && !writeBaseCn))
                {
                    continue;
                }

                child.Properties[name].Value = value;
            }

            ApplyExtensionChanges(child);
            child.CommitChanges();
            Entry = child;
            _pending.Clear();
            _extensionCache.Clear();
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
        CheckDisposedOrDeleted();
        if (context is null)
        {
            throw new InvalidOperationException("The target context cannot be null.");
        }

        if (ReferenceEquals(context, ContextRef))
        {
            Save();
            return;
        }

        if (context.ContextType != ContextRef.ContextType)
        {
            throw new InvalidOperationException(
                "The destination context must have the same ContextType as the principal context.");
        }

        if (Entry is null)
        {
            ContextRef = context;
            Save();
            return;
        }

        if (!string.Equals(
                context.DefaultNamingContext,
                ContextRef.DefaultNamingContext,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PlatformNotSupportedException(
                "Moving a persisted principal between AD domains requires ADSI's cross-store move " +
                "support and is not available through this LDAP port. Different domain controllers " +
                "for the same AD domain are supported.");
        }

        var originalContext = ContextRef;
        var originalEntry = Entry;
        var currentDn = Entry.DistinguishedName;
        var currentParent = LdapDistinguishedName.Parent(currentDn);
        var moved = !string.Equals(currentParent, context.Container, StringComparison.OrdinalIgnoreCase);

        try
        {
            if (moved)
            {
                using var target = context.CreateDirectoryEntry(context.Container);
                originalEntry.MoveTo(target);
                currentDn = originalEntry.DistinguishedName;
            }

            OnBeforeSave();
            ApplyExtensionChanges(originalEntry);
            originalEntry.CommitChanges();
            _extensionCache.Clear();

            var destinationEntry = context.CreateDirectoryEntry(currentDn);
            Entry = destinationEntry;
            ContextRef = context;
            try
            {
                OnAfterSave();
            }
            catch
            {
                destinationEntry.Dispose();
                Entry = originalEntry;
                ContextRef = originalContext;
                throw;
            }

            originalEntry.Dispose();
        }
        catch
        {
            Entry = originalEntry;
            ContextRef = originalContext;
            if (moved)
            {
                try
                {
                    using var originalParent = originalContext.CreateDirectoryEntry(currentParent!);
                    originalEntry.MoveTo(originalParent);
                }
                catch
                {
                    // Preserve the original failure. The server may already have
                    // rolled back the move, or the rollback may require admin repair.
                }
            }

            throw;
        }
    }

    /// <summary>Deletes this principal from the directory.</summary>
    public void Delete()
    {
        CheckDisposedOrDeleted();
        if (Entry is null)
        {
            throw new InvalidOperationException("Cannot delete a principal that has not been saved.");
        }

        Entry.DeleteTree();
        Entry.Dispose();
        Entry = null;
        _deleted = true;
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
    public object? GetUnderlyingObject()
    {
        CheckDisposedOrDeleted();
        return Entry ?? throw new InvalidOperationException(
            "The principal must be saved before its underlying object can be read.");
    }

    /// <summary>The type behind <see cref="GetUnderlyingObject"/>.</summary>
    public Type GetUnderlyingObjectType()
    {
        CheckDisposedOrDeleted();
        return typeof(DirectoryEntry);
    }

    /// <summary>Reads an arbitrary directory attribute for an extension class.</summary>
    protected object?[] ExtensionGet(string attribute)
    {
        CheckDisposedOrDeleted();
        if (attribute is null)
        {
            throw new ArgumentException("The attribute cannot be null.", nameof(attribute));
        }

        if (_extensionCache.TryGetValue(attribute, out var staged))
        {
            return staged.ToArray();
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
        CheckDisposedOrDeleted();
        if (attribute is null)
        {
            throw new ArgumentException("The attribute cannot be null.", nameof(attribute));
        }

        ValidateExtensionValue(value);
        _extensionCache[attribute] = value is object?[] array
            ? array.ToArray()
            : new object?[] { value };
        SetQueryFilter(
            $"extension:{attribute}",
            PrincipalQueryFilterKind.Extension,
            attribute,
            _extensionCache[attribute]);
    }

    private void ApplyExtensionChanges(DirectoryEntry entry)
    {
        foreach (var (attribute, values) in _extensionCache)
        {
            if (values.Length == 1 && values[0] is null)
            {
                entry.Properties[attribute].Clear();
            }
            else
            {
                entry.Properties[attribute].Value = values;
            }
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
        CheckDisposedOrDeleted();
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Value?.ToString();
        }

        return _pending.TryGetValue(attributeName, out var value) ? value?.ToString() : null;
    }

    private protected IEnumerable<string> GetValues(string attributeName)
    {
        CheckDisposedOrDeleted();
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
        CheckDisposedOrDeleted();
        var array = values.Cast<object>().ToArray();
        if (Entry is not null)
        {
            Entry.Properties[attributeName].Value = array;
        }
        else
        {
            _pending[attributeName] = array;
            SetQueryFilter(attributeName, PrincipalQueryFilterKind.StringCollection, attributeName, array);
        }
    }

    private protected object? GetValue(string attributeName)
    {
        CheckDisposedOrDeleted();
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Value;
        }

        return _pending.TryGetValue(attributeName, out var value) ? value : null;
    }

    private protected IEnumerable<object> GetRawValues(string attributeName)
    {
        CheckDisposedOrDeleted();
        if (Entry is not null)
        {
            return Entry.Properties[attributeName].Cast<object>().ToArray();
        }

        return _pending.TryGetValue(attributeName, out var value) && value is IEnumerable<object> many
            ? many.ToArray()
            : Array.Empty<object>();
    }

    private protected void SetValue(string attributeName, object? value)
    {
        CheckDisposedOrDeleted();
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
            if (value is null)
            {
                RemoveQueryFilter(attributeName);
            }
            else
            {
                SetQueryFilter(attributeName, PrincipalQueryFilterKind.Binary, attributeName, value);
            }
        }
    }

    internal void SetAdvancedFilter(string attribute, string value, MatchType match)
    {
        CheckDisposedOrDeleted();
        _advancedFilters[attribute] = AdvancedFilters.ToLdapCondition(attribute, value, match);
    }

    internal void SetAdvancedFilter(string key, string condition)
    {
        CheckDisposedOrDeleted();
        _advancedFilters[key] = condition;
    }

    internal IEnumerable<string> AdvancedFilterConditions
    {
        get
        {
            CheckDisposedOrDeleted();
            return _advancedFilters.Values;
        }
    }

    private protected void SetQueryFilter(
        string key,
        PrincipalQueryFilterKind kind,
        string attribute,
        object? value,
        uint bit = 0)
    {
        CheckDisposedOrDeleted();
        _queryFilters[key] = new PrincipalQueryFilter(key, kind, attribute, value, bit);
    }

    private protected void RemoveQueryFilter(string key)
    {
        CheckDisposedOrDeleted();
        _queryFilters.Remove(key);
    }

    /// <summary>Sets a single string attribute, on the entry or as a pending value.</summary>
    private protected void SetString(string attributeName, string? value)
    {
        CheckDisposedOrDeleted();
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
            SetQueryFilter(
                attributeName,
                PrincipalQueryFilterKind.String,
                attributeName.Equals("cn", StringComparison.OrdinalIgnoreCase) ? "name" : attributeName,
                value);
        }
    }

    /// <summary>The values staged before the object is saved.</summary>
    private protected IReadOnlyDictionary<string, object?> PendingValues => _pending;

    public virtual void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Entry?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Throws when this principal can no longer be used.</summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    protected void CheckDisposedOrDeleted()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().ToString());
        }

        if (_deleted)
        {
            throw new InvalidOperationException("The principal has been deleted.");
        }
    }
}
