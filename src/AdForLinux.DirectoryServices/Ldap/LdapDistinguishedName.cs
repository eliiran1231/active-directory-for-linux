namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>Helpers for splitting RFC 4514 distinguished names.</summary>
internal static class LdapDistinguishedName
{
    public static string RelativeName(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
        {
            return string.Empty;
        }

        var separator = FirstRdnSeparator(distinguishedName);
        return separator < 0 ? distinguishedName : distinguishedName[..separator];
    }

    public static string? Parent(string distinguishedName)
    {
        var separator = FirstRdnSeparator(distinguishedName);
        return separator < 0 ? null : distinguishedName[(separator + 1)..];
    }

    private static int FirstRdnSeparator(string distinguishedName)
    {
        for (var index = 0; index < distinguishedName.Length; index++)
        {
            if (distinguishedName[index] != ',')
            {
                continue;
            }

            var precedingBackslashes = 0;
            for (var previous = index - 1;
                 previous >= 0 && distinguishedName[previous] == '\\';
                 previous--)
            {
                precedingBackslashes++;
            }

            // An odd run escapes the comma. An even run represents complete
            // escaped-backslash pairs, so the comma is an RDN separator.
            if (precedingBackslashes % 2 == 0)
            {
                return index;
            }
        }

        return -1;
    }
}
