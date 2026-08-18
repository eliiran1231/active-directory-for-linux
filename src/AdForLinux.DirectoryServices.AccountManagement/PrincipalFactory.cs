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

        var principalType = SelectPrincipalType(classes);
        if (principalType == typeof(ComputerPrincipal))
        {
            return new ComputerPrincipal(context, entry);
        }

        if (principalType == typeof(GroupPrincipal))
        {
            return new GroupPrincipal(context, entry);
        }

        if (principalType == typeof(UserPrincipal))
        {
            return new UserPrincipal(context, entry);
        }

        if (principalType == typeof(ForeignSecurityPrincipal))
        {
            return new ForeignSecurityPrincipal(context, entry);
        }

        // Contacts and other non-principal directory objects are not modelled.
        return null;
    }

    internal static Type? SelectPrincipalType(IEnumerable<string?> classes)
    {
        var values = classes.ToArray();
        if (values.Contains("computer", StringComparer.OrdinalIgnoreCase))
        {
            return typeof(ComputerPrincipal);
        }

        if (values.Contains("group", StringComparer.OrdinalIgnoreCase))
        {
            return typeof(GroupPrincipal);
        }

        if (values.Contains("user", StringComparer.OrdinalIgnoreCase))
        {
            return typeof(UserPrincipal);
        }

        return values.Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase)
            ? typeof(ForeignSecurityPrincipal)
            : null;
    }
}
