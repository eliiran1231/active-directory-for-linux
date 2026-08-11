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
            // The value-only overload searches the common identity attributes.
            return $"(|(sAMAccountName={value})(userPrincipalName={value})(cn={value})(distinguishedName={value}))";
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

    private static byte[] ParseGuid(string value) =>
        System.Guid.TryParse(value, out var guid)
            ? guid.ToByteArray()
            : throw new ArgumentException("The identity value is not a valid GUID.", nameof(value));
}
