namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Which attribute an identity value means, for <c>FindByIdentity</c>. Values
/// and order match Microsoft.
/// </summary>
public enum IdentityType
{
    /// <summary>The <c>sAMAccountName</c>.</summary>
    SamAccountName = 0,

    /// <summary>The object name (<c>cn</c>).</summary>
    Name = 1,

    /// <summary>The <c>userPrincipalName</c> (user@domain).</summary>
    UserPrincipalName = 2,

    /// <summary>The distinguished name.</summary>
    DistinguishedName = 3,

    /// <summary>The security identifier (SID).</summary>
    Sid = 4,

    /// <summary>The object GUID.</summary>
    Guid = 5,
}
