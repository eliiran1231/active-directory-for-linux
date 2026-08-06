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
}
