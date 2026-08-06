using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Builds the right principal type for a directory object, based on its
/// objectClass. Used when reading group members, where each member may be a
/// user or another group.
/// </summary>
internal static class PrincipalFactory
{
    public static Principal? FromEntry(PrincipalContext context, DirectoryEntry entry)
    {
        var classes = entry.Properties["objectClass"]
            .Cast<object>()
            .Select(value => value.ToString())
            .ToArray();

        if (classes.Contains("group", StringComparer.OrdinalIgnoreCase))
        {
            return new GroupPrincipal(context, entry);
        }

        if (classes.Contains("user", StringComparer.OrdinalIgnoreCase))
        {
            return new UserPrincipal(context, entry);
        }

        // Contacts, computers and the like are not modelled yet.
        return null;
    }
}
