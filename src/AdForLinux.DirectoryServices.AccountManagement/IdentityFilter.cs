using System.ComponentModel;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Builds the LDAP filter piece that matches an identity value, escaping the
/// value so parentheses, stars, and backslashes are safe (RFC 4515).
/// </summary>
internal static class IdentityFilter
{
    public static string Build(IdentityType? identityType, string identityValue)
    {
        var value = LdapFilter.EscapeValue(identityValue);

        if (identityType is null)
        {
            throw new ArgumentNullException(nameof(identityType));
        }

        return identityType switch
        {
            IdentityType.SamAccountName => $"(sAMAccountName={value})",
            IdentityType.Name => $"(cn={value})",
            IdentityType.UserPrincipalName => $"(userPrincipalName={value})",
            IdentityType.DistinguishedName => $"(distinguishedName={value})",
            IdentityType.Guid => $"(objectGUID={LdapFilter.EscapeBytes(ParseGuid(identityValue))})",
            IdentityType.Sid => $"(objectSid={LdapFilter.EscapeBytes(SidCodec.Parse(identityValue))})",
            _ => throw new InvalidEnumArgumentException(
                nameof(identityType), (int)identityType.Value, typeof(IdentityType)),
        };
    }

    public static IReadOnlyList<string> BuildValueOnlyCandidates(string identityValue)
    {
        // AccountManagement tries these identity schemes in order and stops at
        // the first scheme that finds an object. Invalid SID/GUID text skips
        // only that scheme and remains eligible as an ordinary name.
        var value = LdapFilter.EscapeValue(identityValue);
        var assertions = new List<string>();
        var separator = identityValue.IndexOf('\\');
        if (separator != identityValue.Length - 1)
        {
            var samAccountName = separator < 0
                ? identityValue
                : identityValue[(separator + 1)..];
            assertions.Add($"(sAMAccountName={LdapFilter.EscapeValue(samAccountName)})");
        }

        assertions.Add($"(userPrincipalName={value})");
        assertions.Add($"(distinguishedName={value})");
        try
        {
            assertions.Add($"(objectSid={LdapFilter.EscapeBytes(SidCodec.Parse(identityValue))})");
        }
        catch (ArgumentException)
        {
        }

        if (Guid.TryParse(identityValue, out var guid))
        {
            assertions.Add($"(objectGUID={LdapFilter.EscapeBytes(guid.ToByteArray())})");
        }

        assertions.Add($"(name={value})");
        return assertions;
    }

    private static byte[] ParseGuid(string value) =>
        System.Guid.TryParse(value, out var guid)
            ? guid.ToByteArray()
            : throw new ArgumentException("The identity value is not a valid GUID.", nameof(value));
}
