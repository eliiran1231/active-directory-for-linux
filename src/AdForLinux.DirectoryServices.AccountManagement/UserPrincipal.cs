using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A user account, like Microsoft's <c>UserPrincipal</c>. Find one with
/// <see cref="FindByIdentity(PrincipalContext, string)"/>, then read its
/// properties.
/// </summary>
[DirectoryRdnPrefix("CN")]
public class UserPrincipal : AuthenticablePrincipal
{
    /// <summary>Starts a new, unsaved user in a context. Saving arrives later.</summary>
    public UserPrincipal(PrincipalContext context) : base(context)
    {
    }

    /// <summary>Starts a new user with its account name, password, and enabled state.</summary>
    public UserPrincipal(PrincipalContext context, string samAccountName, string password, bool enabled)
        : base(context, samAccountName, password, enabled)
    {
    }

    /// <summary>
    /// Gets the operating-system user under which the current thread runs.
    /// This requires Windows SID lookup and serverless domain discovery, which
    /// are not available in this Linux LDAP port.
    /// </summary>
    public static UserPrincipal Current => throw new InvalidOperationException(
        "UserPrincipal.Current requires Windows SID lookup and serverless domain discovery. " +
        "On Linux, create a PrincipalContext with an explicit domain controller and call FindByIdentity instead.");

    public static new PrincipalSearchResult<UserPrincipal> FindByLockoutTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByLockoutTime<UserPrincipal>(context, time, type);
    public static new PrincipalSearchResult<UserPrincipal> FindByLogonTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByLogonTime<UserPrincipal>(context, time, type);
    public static new PrincipalSearchResult<UserPrincipal> FindByExpirationTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByExpirationTime<UserPrincipal>(context, time, type);
    public static new PrincipalSearchResult<UserPrincipal> FindByBadPasswordAttempt(PrincipalContext context, DateTime time, MatchType type) =>
        FindByBadPasswordAttempt<UserPrincipal>(context, time, type);
    public static new PrincipalSearchResult<UserPrincipal> FindByPasswordSetTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByPasswordSetTime<UserPrincipal>(context, time, type);

    internal UserPrincipal(PrincipalContext context, DirectoryEntry entry) : base(context)
    {
        AttachExisting(context, entry);
    }

    private protected override string CreateObjectClass => "user";

    internal override string CategoryFilter => "(objectCategory=user)(objectClass=user)";

    /// <summary>
    /// Every authorization group this user belongs to, including transitive
    /// membership and the primary group.
    /// </summary>
    public PrincipalSearchResult<Principal> GetAuthorizationGroups() =>
        GetAuthorizationGroupsCore();

    /// <summary>The first name (<c>givenName</c>).</summary>
    public string? GivenName
    {
        get => GetString("givenName");
        set => SetString("givenName", value);
    }

    /// <summary>The last name (<c>sn</c>).</summary>
    public string? Surname
    {
        get => GetString("sn");
        set => SetString("sn", value);
    }

    /// <summary>The email address (<c>mail</c>).</summary>
    public string? EmailAddress
    {
        get => GetString("mail");
        set => SetString("mail", value);
    }

    /// <summary>The phone number (<c>telephoneNumber</c>).</summary>
    public string? VoiceTelephoneNumber
    {
        get => GetString("telephoneNumber");
        set => SetString("telephoneNumber", value);
    }

    /// <summary>The middle name.</summary>
    public string? MiddleName
    {
        get => GetString("middleName");
        set => SetString("middleName", value);
    }

    /// <summary>The employee id.</summary>
    public string? EmployeeId
    {
        get => GetString("employeeID");
        set => SetString("employeeID", value);
    }

    /// <summary>Finds a user by a value across the common identity attributes.</summary>
    public static new UserPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        (UserPrincipal?)FindByIdentityWithType(context, typeof(UserPrincipal), identityValue);

    /// <summary>Finds a user by a specific identity type.</summary>
    public static new UserPrincipal? FindByIdentity(
        PrincipalContext context, IdentityType identityType, string identityValue) =>
        (UserPrincipal?)FindByIdentityWithType(context, typeof(UserPrincipal), identityType, identityValue);
}
