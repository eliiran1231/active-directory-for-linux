using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Tells text attributes from binary ones. LDAP sends every value as raw bytes,
/// so we decode text attributes to strings and leave binary ones as byte[].
/// This is the small, well-known set of AD attributes that are truly binary;
/// everything else is treated as text (UTF-8), like the common tools do.
/// </summary>
internal static class LdapAttributeSchema
{
    private static readonly HashSet<string> BinaryAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectGUID",
        "objectSid",
        "sIDHistory",
        "mS-DS-ConsistencyGuid",
        "msDS-ConsistencyGuid",
        "schemaIDGUID",
        "attributeSecurityGUID",
        "nTSecurityDescriptor",
        "thumbnailPhoto",
        "jpegPhoto",
        "photo",
        "userCertificate",
        "userSMIMECertificate",
        "cACertificate",
        "tokenGroups",
        "tokenGroupsGlobalAndUniversal",
        "logonHours",
        "msExchMailboxGuid",
    };

    /// <summary>True if this attribute's values should stay as raw bytes.</summary>
    public static bool IsBinary(string attributeName) => BinaryAttributes.Contains(attributeName);

    /// <summary>
    /// Verifies that an AD attribute has the Object(DS-DN) schema syntax required
    /// by attribute-scoped queries: attributeSyntax 2.5.5.1 and oMSyntax 127.
    /// </summary>
    public static void EnsureDistinguishedNameAttribute(LdapConnection connection, string attributeName)
    {
        var rootDse = RootDse.Read(connection, "schemaNamingContext");
        if (!rootDse.TryGetValue("schemaNamingContext", out var schemaNamingContext) ||
            string.IsNullOrEmpty(schemaNamingContext))
        {
            throw InvalidAttributeSyntax(attributeName, "the server did not expose schemaNamingContext");
        }

        var request = new SearchRequest(
            schemaNamingContext,
            $"(&(objectClass=attributeSchema)(lDAPDisplayName={EscapeFilterValue(attributeName)}))",
            ProtocolScope.OneLevel,
            "attributeSyntax",
            "oMSyntax");
        var response = (SearchResponse)connection.SendRequest(request);

        if (response.Entries.Count != 1)
        {
            throw InvalidAttributeSyntax(attributeName, "no matching attributeSchema object was found");
        }

        var entry = response.Entries[0];
        var attributeSyntax = FirstString(entry, "attributeSyntax");
        var omSyntax = FirstString(entry, "oMSyntax");
        if (!string.Equals(attributeSyntax, "2.5.5.1", StringComparison.Ordinal) ||
            !string.Equals(omSyntax, "127", StringComparison.Ordinal))
        {
            throw InvalidAttributeSyntax(
                attributeName,
                $"schema syntax was attributeSyntax={attributeSyntax ?? "<missing>"}, " +
                $"oMSyntax={omSyntax ?? "<missing>"}, not Object(DS-DN)");
        }
    }

    private static string? FirstString(SearchResultEntry entry, string attributeName)
    {
        var attribute = entry.Attributes[attributeName];
        return attribute?.Count > 0
            ? attribute.GetValues(typeof(string)).Cast<string>().FirstOrDefault()
            : null;
    }

    private static DirectoryOperationException InvalidAttributeSyntax(string attributeName, string reason) =>
        new($"AttributeScopeQuery attribute '{attributeName}' is invalid: {reason}. " +
            "LDAP invalidAttributeSyntax (21).");

    private static string EscapeFilterValue(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}
