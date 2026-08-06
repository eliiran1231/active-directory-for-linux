namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Builds the LDAP filter piece that matches an identity value, escaping the
/// value so parentheses, stars, and backslashes are safe (RFC 4515).
/// </summary>
internal static class IdentityFilter
{
    public static string Build(IdentityType? identityType, string identityValue)
    {
        var value = Escape(identityValue);

        if (identityType is null)
        {
            // The value-only overload searches the common identity attributes.
            return $"(|(sAMAccountName={value})(userPrincipalName={value})(cn={value})(distinguishedName={value}))";
        }

        return identityType switch
        {
            IdentityType.SamAccountName => $"(sAMAccountName={value})",
            IdentityType.Name => $"(cn={value})",
            IdentityType.UserPrincipalName => $"(userPrincipalName={value})",
            IdentityType.DistinguishedName => $"(distinguishedName={value})",
            _ => throw new NotSupportedException(
                $"FindByIdentity by {identityType} is not supported yet."),
        };
    }

    public static string Escape(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}
