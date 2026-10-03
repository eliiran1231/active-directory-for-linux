namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>LDAP attributes mapped by the public principal properties.</summary>
internal static class PrincipalSearchProjection
{
    private static readonly string[] PrincipalAttributes =
    [
        "displayname", "description", "samaccountname", "userprincipalname",
        "objectguid", "objectsid", "objectclass", "name", "distinguishedname",
    ];

    private static readonly string[] AuthenticableAttributes =
    [
        "useraccountcontrol", "usercertificate", "badpasswordtime", "accountexpires",
        "lastlogon", "lastlogontimestamp", "lockouttime", "badpwdcount", "pwdlastset",
    ];

    // Multiple principal properties map to useraccountcontrol. Keep their
    // multiplicity in the native StringCollection, as AccountManagement does.
    private static readonly string[] UserAttributes =
    [
        "givenname", "middlename", "sn", "mail", "telephonenumber", "employeeid",
        "userworkstations", "logonhours", "useraccountcontrol", "useraccountcontrol",
        "homedirectory", "homedrive", "scriptpath", "useraccountcontrol",
        "useraccountcontrol", "useraccountcontrol",
    ];

    internal static IEnumerable<string> For(Type type)
    {
        IEnumerable<string> attributes = PrincipalAttributes;
        if (typeof(AuthenticablePrincipal).IsAssignableFrom(type))
            attributes = attributes.Concat(AuthenticableAttributes);
        if (typeof(UserPrincipal).IsAssignableFrom(type))
            attributes = attributes.Concat(UserAttributes);
        else if (typeof(GroupPrincipal).IsAssignableFrom(type))
            attributes = attributes.Concat(new[] { "grouptype", "grouptype" });
        else if (typeof(ComputerPrincipal).IsAssignableFrom(type))
            attributes = attributes.Append("serviceprincipalname");
        attributes = attributes.Append("objectClass");

        if (type == typeof(UserPrincipal) || type == typeof(GroupPrincipal)
            || type == typeof(ComputerPrincipal) || type == typeof(AuthenticablePrincipal)
            || type == typeof(Principal))
            return attributes;

        return attributes.Concat(type.GetProperties()
            .SelectMany(property => property.GetCustomAttributes(typeof(DirectoryPropertyAttribute), true)
                .Cast<DirectoryPropertyAttribute>())
            .Select(attribute => attribute.SchemaAttributeName).OfType<string>()).Distinct(StringComparer.Ordinal);
    }
}
