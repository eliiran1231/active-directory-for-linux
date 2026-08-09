using System.Text;
using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// A principal that can log on (a user), like Microsoft's
/// <c>AuthenticablePrincipal</c>. Adds account state and password operations on
/// top of <see cref="Principal"/>.
/// </summary>
[DirectoryRdnPrefix("CN")]
public abstract class AuthenticablePrincipal : Principal
{
    // userAccountControl bits.
    private const int AccountDisabled = 0x2;
    private const int PasswordNotRequiredFlag = 0x20;
    private const int NormalAccount = 0x200;
    private const int NotDelegated = 0x100000;
    private const int PasswordDoesNotExpire = 0x10000;
    private AdvancedFilters? _advancedSearchFilter;
    private string? _passwordToSet;
    private bool? _enabledAfterPassword;

    protected internal AuthenticablePrincipal(PrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        ContextRef = context;
    }

    protected internal AuthenticablePrincipal(
        PrincipalContext context,
        string samAccountName,
        string password,
        bool enabled)
        : this(context)
    {
        if (samAccountName is null || password is null)
        {
            throw new ArgumentException("The account name and password cannot be null.");
        }

        SamAccountName = samAccountName;
        Name = samAccountName;
        _passwordToSet = password;
        Enabled = enabled;
    }

    public virtual AdvancedFilters AdvancedSearchFilter =>
        _advancedSearchFilter ??= new AdvancedFilters(this);

    private protected virtual int DefaultUserAccountControl => NormalAccount;

    /// <summary>
    /// Whether the account is enabled. Reads and writes the ACCOUNTDISABLE bit
    /// of <c>userAccountControl</c>. Setting it needs a <see cref="Principal.Save"/>.
    /// Null before the object is saved.
    /// </summary>
    public bool? Enabled
    {
        get
        {
            var flags = ReadUserAccountControl();
            return flags is null ? null : (flags.Value & AccountDisabled) == 0;
        }
        set
        {
            if (value is not null)
            {
                if (_passwordToSet is not null && Entry is null)
                {
                    // AD requires the password to be established before the
                    // account is enabled. Remember the requested final state,
                    // but always create a constructor-initialized account disabled.
                    _enabledAfterPassword = value.Value;
                    SetUserAccountControlBit(AccountDisabled, on: true);
                }
                else
                {
                    SetUserAccountControlBit(AccountDisabled, on: !value.Value);
                }
            }
        }
    }

    /// <summary>
    /// When the account expires, or null if it never does. Setting it needs a
    /// <see cref="Principal.Save"/>. Times are UTC.
    /// </summary>
    public DateTime? AccountExpirationDate
    {
        get => AdFileTime.ToDateTime(GetString("accountExpires"));
        set => SetString("accountExpires", AdFileTime.FromDateTime(value));
    }

    /// <summary>When the account was locked out, or null if it is not locked.</summary>
    public DateTime? AccountLockoutTime => AdFileTime.ToDateTime(GetString("lockoutTime"));

    /// <summary>
    /// When the account last logged on, or null if never. Read only. This is
    /// the replicated <c>lastLogonTimestamp</c> when present, which can lag by
    /// days; otherwise the local <c>lastLogon</c> of the server we asked.
    /// </summary>
    public DateTime? LastLogon =>
        AdFileTime.ToDateTime(GetString("lastLogonTimestamp"))
        ?? AdFileTime.ToDateTime(GetString("lastLogon"));

    /// <summary>
    /// When the password was last set, or null if the user must change it at
    /// next logon.
    /// </summary>
    public DateTime? LastPasswordSet => AdFileTime.ToDateTime(GetString("pwdLastSet"));

    /// <summary>How many bad password attempts have been counted.</summary>
    public int BadLogonCount =>
        int.TryParse(GetString("badPwdCount"), out var count) ? count : 0;

    /// <summary>When the last bad password attempt happened, or null.</summary>
    public DateTime? LastBadPasswordAttempt => AdFileTime.ToDateTime(GetString("badPasswordTime"));

    /// <summary>Whether the password never expires. Needs a Save.</summary>
    public bool PasswordNeverExpires
    {
        get => HasUserAccountControlBit(PasswordDoesNotExpire);
        set => SetUserAccountControlBit(PasswordDoesNotExpire, value);
    }

    /// <summary>Whether the account may have no password. Needs a Save.</summary>
    public bool PasswordNotRequired
    {
        get => HasUserAccountControlBit(PasswordNotRequiredFlag);
        set => SetUserAccountControlBit(PasswordNotRequiredFlag, value);
    }

    /// <summary>Whether the account may be delegated. Needs a Save.</summary>
    public bool DelegationPermitted
    {
        // Stored inverted: the NOT_DELEGATED bit means delegation is blocked.
        get => !HasUserAccountControlBit(NotDelegated);
        set => SetUserAccountControlBit(NotDelegated, !value);
    }

    /// <summary>The home directory path.</summary>
    public string? HomeDirectory
    {
        get => GetString("homeDirectory");
        set => SetString("homeDirectory", value);
    }

    /// <summary>The home drive letter.</summary>
    public string? HomeDrive
    {
        get => GetString("homeDrive");
        set => SetString("homeDrive", value);
    }

    /// <summary>The logon script path.</summary>
    public string? ScriptPath
    {
        get => GetString("scriptPath");
        set => SetString("scriptPath", value);
    }

    /// <summary>
    /// Whether the account is locked out right now. An account stays stamped
    /// with a lockout time after the lockout has expired, so we compare it with
    /// the domain's lockout duration, like Microsoft does.
    /// </summary>
    public bool IsAccountLockedOut()
    {
        var lockedAt = AccountLockoutTime;
        if (lockedAt is null)
        {
            return false;
        }

        var duration = ReadDomainLockoutDuration();
        if (duration is null)
        {
            // Locked until an administrator unlocks it.
            return true;
        }

        return DateTime.UtcNow < lockedAt.Value + duration.Value;
    }

    private TimeSpan? ReadDomainLockoutDuration()
    {
        // lockoutDuration lives on the domain object at the naming context root,
        // which is not the container when the context is scoped.
        using var domain = ContextRef.CreateDirectoryEntry(ContextRef.DefaultNamingContext);
        return AdFileTime.ToDuration(domain.Properties["lockoutDuration"].Value?.ToString());
    }

    private bool HasUserAccountControlBit(int bit)
    {
        var flags = ReadUserAccountControl();
        return flags is not null && (flags.Value & bit) != 0;
    }

    /// <summary>
    /// Resets the account password (admin reset). Takes effect immediately, so
    /// the object must already be saved. Requires a TLS connection, which this
    /// port always uses.
    /// </summary>
    public void SetPassword(string newPassword)
    {
        var entry = RequireSaved();

        // AD wants the password quoted and encoded as little-endian UTF-16.
        var quoted = "\"" + newPassword + "\"";
        var bytes = Encoding.Unicode.GetBytes(quoted);
        entry.ReplaceAttributeImmediate("unicodePwd", bytes);
    }

    /// <summary>Unlocks a locked-out account. Takes effect immediately.</summary>
    public void UnlockAccount()
    {
        var entry = RequireSaved();
        entry.ReplaceAttributeImmediate("lockoutTime", "0");
    }

    /// <summary>Forces the password to be changed at next logon. Immediate.</summary>
    public void ExpirePasswordNow()
    {
        var entry = RequireSaved();
        entry.ReplaceAttributeImmediate("pwdLastSet", "0");
    }

    private protected int? ReadUserAccountControl()
    {
        var raw = GetString("userAccountControl");
        return raw is not null && int.TryParse(raw, out var flags) ? flags : null;
    }

    private protected void SetUserAccountControlBit(int bit, bool on)
    {
        var flags = ReadUserAccountControl() ?? DefaultUserAccountControl;
        flags = on ? flags | bit : flags & ~bit;
        SetString("userAccountControl", flags.ToString());
    }

    private DirectoryEntry RequireSaved() =>
        Entry ?? throw new InvalidOperationException(
            "The account must be saved before this operation.");

    private protected override void OnAfterSave()
    {
        base.OnAfterSave();
        if (_passwordToSet is not null)
        {
            SetPassword(_passwordToSet);
            _passwordToSet = null;
        }

        if (_enabledAfterPassword is not null)
        {
            Enabled = _enabledAfterPassword.Value;
            Entry!.CommitChanges();
            _enabledAfterPassword = null;
        }
    }

    public static PrincipalSearchResult<AuthenticablePrincipal> FindByLockoutTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, "lockoutTime", time, type);
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByLogonTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, "lastLogonTimestamp", time, type);
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByExpirationTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, "accountExpires", time, type);
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByBadPasswordAttempt(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, "badPasswordTime", time, type);
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByPasswordSetTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, "pwdLastSet", time, type);

    protected static PrincipalSearchResult<T> FindByLockoutTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, "lockoutTime", time, type);
    protected static PrincipalSearchResult<T> FindByLogonTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, "lastLogonTimestamp", time, type);
    protected static PrincipalSearchResult<T> FindByExpirationTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, "accountExpires", time, type);
    protected static PrincipalSearchResult<T> FindByBadPasswordAttempt<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, "badPasswordTime", time, type);
    protected static PrincipalSearchResult<T> FindByPasswordSetTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, "pwdLastSet", time, type);

    private static PrincipalSearchResult<T> FindByAdvancedFilter<T>(PrincipalContext context, string attribute, DateTime time, MatchType type)
        where T : AuthenticablePrincipal
    {
        ArgumentNullException.ThrowIfNull(context);
        var category = typeof(T) == typeof(ComputerPrincipal)
            ? "(objectCategory=computer)"
            : typeof(T) == typeof(UserPrincipal)
                ? "(objectCategory=person)(objectClass=user)"
                : "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        var value = time.ToUniversalTime().ToFileTimeUtc().ToString();
        var condition = AdvancedFilters.ToLdapCondition(attribute, value, type);
        using var root = context.CreateDirectoryEntry(context.Container);
        using var searcher = new DirectorySearcher(root, $"(&{category}{condition})") { PageSize = 500 };
        using var results = searcher.FindAll();
        var principals = new List<T>();
        foreach (var result in results.Cast<SearchResult>())
        {
            var entry = result.GetDirectoryEntry();
            if (PrincipalFactory.FromEntry(context, entry) is T principal)
            {
                principals.Add(principal);
            }
            else
            {
                entry.Dispose();
            }
        }

        return new PrincipalSearchResult<T>(principals);
    }
}
