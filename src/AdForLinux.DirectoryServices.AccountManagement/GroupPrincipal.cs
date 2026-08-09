using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A group, like Microsoft's <c>GroupPrincipal</c>. Find one with
/// <see cref="FindByIdentity(PrincipalContext, string)"/>, or make a new one and
/// call <c>Save</c>. Manage membership through <see cref="Members"/>.
/// </summary>
public class GroupPrincipal : Principal
{
    // groupType flags from AD.
    private const int ScopeLocal = 0x4;        // domain local (resource group)
    private const int ScopeGlobal = 0x2;       // global (account group)
    private const int ScopeUniversal = 0x8;
    private const int ScopeMask = ScopeLocal | ScopeGlobal | ScopeUniversal | 0x1;
    private const int SecurityEnabled = unchecked((int)0x80000000);

    // What Microsoft creates by default: a global security group.
    private const int DefaultGroupType = ScopeGlobal | SecurityEnabled;

    private PrincipalCollection? _members;

    /// <summary>Starts a new, unsaved group in a context.</summary>
    public GroupPrincipal(PrincipalContext context)
    {
        ContextRef = context;
    }

    /// <summary>Starts a new, unsaved group with a name.</summary>
    public GroupPrincipal(PrincipalContext context, string samAccountName)
    {
        ContextRef = context;
        Name = samAccountName;
        SamAccountName = samAccountName;
    }

    internal GroupPrincipal(PrincipalContext context, DirectoryEntry entry)
    {
        AttachExisting(context, entry);
    }

    private protected override string CreateObjectClass => "group";

    internal override string CategoryFilter => "(objectCategory=group)";

    /// <summary>The members of this group. Changes need a <see cref="Principal.Save"/>.</summary>
    public PrincipalCollection Members => _members ??= new PrincipalCollection(this);

    /// <summary>Returns this group's direct members.</summary>
    public PrincipalSearchResult<Principal> GetMembers() => GetMembers(recursive: false);

    /// <summary>
    /// Returns this group's members. When <paramref name="recursive"/> is
    /// true, members of nested groups are included as well.
    /// </summary>
    public PrincipalSearchResult<Principal> GetMembers(bool recursive)
    {
        if (!recursive)
        {
            // Materialize the collection so the returned result owns and
            // disposes the principals, just like other PrincipalSearchResult
            // APIs. This also keeps staged membership changes visible.
            return new PrincipalSearchResult<Principal>(Members.ToList());
        }

        var groupDn = RequireEntry().DistinguishedName;
        // Recursive results contain only leaves. Groups are traversal nodes,
        // whereas GetMembers(false) may return direct group members.
        var filter = $"(&(memberOf:1.2.840.113556.1.4.1941:={IdentityFilter.Escape(groupDn)})(!(objectClass=group)))";
        // GetMembers is not constrained by PrincipalContext.Container: group
        // members in other containers must still be returned.
        var root = ContextRef.CreateDirectoryEntry(ContextRef.DefaultNamingContext);
        try
        {
            using var searcher = new DirectorySearcher(root, filter) { PageSize = 500 };
            var members = new List<Principal>();
            foreach (var result in searcher.FindAll())
            {
                var entry = result.GetDirectoryEntry();
                var principal = PrincipalFactory.FromEntry(ContextRef, entry);
                if (principal is null)
                {
                    entry.Dispose();
                    continue;
                }

                members.Add(principal);
            }

            return new PrincipalSearchResult<Principal>(members);
        }
        finally
        {
            root.Dispose();
        }
    }

    /// <summary>
    /// How widely the group can be used. Null before the object is saved and no
    /// scope was set.
    /// </summary>
    public GroupScope? GroupScope
    {
        get
        {
            var groupType = ReadGroupType();
            if (groupType is null)
            {
                return null;
            }

            if ((groupType.Value & ScopeUniversal) != 0)
            {
                return AccountManagement.GroupScope.Universal;
            }

            return (groupType.Value & ScopeLocal) != 0
                ? AccountManagement.GroupScope.Local
                : AccountManagement.GroupScope.Global;
        }
        set
        {
            if (value is null)
            {
                return;
            }

            var bit = value switch
            {
                AccountManagement.GroupScope.Local => ScopeLocal,
                AccountManagement.GroupScope.Universal => ScopeUniversal,
                _ => ScopeGlobal,
            };

            var groupType = ReadGroupType() ?? DefaultGroupType;
            WriteGroupType((groupType & ~ScopeMask) | bit);
        }
    }

    /// <summary>
    /// True for a security group, false for a distribution group. Null before
    /// the object is saved and no value was set.
    /// </summary>
    public bool? IsSecurityGroup
    {
        get
        {
            var groupType = ReadGroupType();
            return groupType is null ? null : (groupType.Value & SecurityEnabled) != 0;
        }
        set
        {
            if (value is null)
            {
                return;
            }

            var groupType = ReadGroupType() ?? DefaultGroupType;
            WriteGroupType(value.Value
                ? groupType | SecurityEnabled
                : groupType & ~SecurityEnabled);
        }
    }

    /// <summary>Finds a group by a value across the common identity attributes.</summary>
    public static GroupPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        Find(context, null, identityValue);

    /// <summary>Finds a group by a specific identity type.</summary>
    public static GroupPrincipal? FindByIdentity(
        PrincipalContext context, IdentityType identityType, string identityValue) =>
        Find(context, identityType, identityValue);

    private static GroupPrincipal? Find(PrincipalContext context, IdentityType? identityType, string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(identityValue);

        var idFilter = IdentityFilter.Build(identityType, identityValue);
        var filter = $"(&(objectCategory=group){idFilter})";

        var root = context.CreateDirectoryEntry(context.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter);
            var result = searcher.FindOne();
            return result is null
                ? null
                : new GroupPrincipal(context, result.GetDirectoryEntry());
        }
        finally
        {
            root.Dispose();
        }
    }

    /// <summary>The underlying entry, or an error if the group is not saved yet.</summary>
    internal DirectoryEntry RequireEntry() =>
        Entry ?? throw new InvalidOperationException(
            "The group must be saved before its members can be used.");

    private int? ReadGroupType()
    {
        var raw = GetString("groupType");
        return raw is not null && int.TryParse(raw, out var groupType) ? groupType : null;
    }

    private void WriteGroupType(int groupType) =>
        SetString("groupType", groupType.ToString());

    private protected override void OnBeforeCreate()
    {
        // A new group needs a groupType; default to a global security group.
        if (ReadGroupType() is null)
        {
            WriteGroupType(DefaultGroupType);
        }
    }

    private protected override void OnAfterSave() => _members?.ApplyChanges();
}
