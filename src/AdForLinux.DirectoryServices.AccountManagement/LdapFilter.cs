namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Encodes values for use in LDAP search filters.</summary>
internal static class LdapFilter
{
    /// <summary>Escapes an assertion value according to RFC 4515.</summary>
    public static string EscapeValue(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");

    /// <summary>Encodes a binary assertion value as escaped hexadecimal octets.</summary>
    public static string EscapeBytes(IEnumerable<byte> value) =>
        string.Concat(value.Select(octet => $"\\{octet:x2}"));
}
