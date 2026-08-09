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

    internal override string CategoryFilter => "(objectCategory=person)(objectClass=user)";

    // userAccountControl bit that forces smartcard logon.
    private const int SmartcardRequired = 0x40000;

    /// <summary>
    /// Whether the account must use a smartcard to log on. Reads and writes the
    /// SMARTCARD_REQUIRED bit of <c>userAccountControl</c>; setting it needs a
    /// <see cref="Principal.Save"/>.
    /// </summary>
    public bool SmartcardLogonRequired
    {
        get
        {
            var flags = ReadUserAccountControl();
            return flags is not null && (flags.Value & SmartcardRequired) != 0;
        }
        set => SetUserAccountControlBit(SmartcardRequired, value);
    }

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
    public static UserPrincipal? FindByIdentity(PrincipalContext context, string identityValue) =>
        Find(context, null, identityValue);

    /// <summary>Finds a user by a specific identity type.</summary>
    public static UserPrincipal? FindByIdentity(
        PrincipalContext context, IdentityType identityType, string identityValue) =>
        Find(context, identityType, identityValue);

    private static UserPrincipal? Find(PrincipalContext context, IdentityType? identityType, string identityValue)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(identityValue);

        var idFilter = IdentityFilter.Build(identityType, identityValue);
        var filter = $"(&(objectCategory=person)(objectClass=user){idFilter})";

        var root = context.CreateDirectoryEntry(context.Container);
        try
        {
            using var searcher = new DirectorySearcher(root, filter);
            var result = searcher.FindOne();
            if (result is null)
            {
                return null;
            }

            return new UserPrincipal(context, result.GetDirectoryEntry());
        }
        finally
        {
            root.Dispose();
        }
    }
}
