using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    private const int ReversiblePasswordEncryption = 0x80;
    private const int NormalAccount = 0x200;
    private const int NotDelegated = 0x100000;
    private const int PasswordDoesNotExpire = 0x10000;
    private const int SmartcardRequired = 0x40000;
    private AdvancedFilters? _advancedSearchFilter;
    private X509Certificate2Collection? _certificates;
    private string[] _certificateThumbprints = Array.Empty<string>();
    private PrincipalValueCollection<string>? _permittedWorkstations;
    private string? _passwordToSet;
    private bool? _enabledAfterPassword;
    private bool _expirePasswordAfterSave;
    private bool? _userCannotChangePassword;

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

    public virtual AdvancedFilters AdvancedSearchFilter
    {
        get
        {
            CheckDisposedOrDeleted();
            return _advancedSearchFilter ??= new AdvancedFilters(this);
        }
    }

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
            CheckDisposedOrDeleted();
            var flags = ReadUserAccountControl();
            return flags is null ? null : (flags.Value & AccountDisabled) == 0;
        }
        set
        {
            CheckDisposedOrDeleted();
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

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

            SetUserAccountControlQuery(nameof(Enabled), AccountDisabled, bitMustBeSet: !value.Value);
        }
    }

    /// <summary>
    /// When the account expires, or null if it never does. Setting it needs a
    /// <see cref="Principal.Save"/>. Times are UTC.
    /// </summary>
    public DateTime? AccountExpirationDate
    {
        get => AdFileTime.ToDateTime(GetString("accountExpires"));
        set
        {
            SetString("accountExpires", AdFileTime.FromDateTime(value));
            RemoveQueryFilter("accountExpires");
            SetQueryFilter(
                nameof(AccountExpirationDate),
                PrincipalQueryFilterKind.AccountExpiration,
                "accountExpires",
                value);
        }
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
        set
        {
            SetUserAccountControlBit(PasswordDoesNotExpire, value);
            SetUserAccountControlQuery(nameof(PasswordNeverExpires), PasswordDoesNotExpire, value);
        }
    }

    /// <summary>Whether the account may have no password. Needs a Save.</summary>
    public bool PasswordNotRequired
    {
        get => HasUserAccountControlBit(PasswordNotRequiredFlag);
        set
        {
            SetUserAccountControlBit(PasswordNotRequiredFlag, value);
            SetUserAccountControlQuery(nameof(PasswordNotRequired), PasswordNotRequiredFlag, value);
        }
    }

    /// <summary>Whether the account may be delegated. Needs a Save.</summary>
    public bool DelegationPermitted
    {
        // Stored inverted: the NOT_DELEGATED bit means delegation is blocked.
        get => !HasUserAccountControlBit(NotDelegated);
        set
        {
            SetUserAccountControlBit(NotDelegated, !value);
            SetUserAccountControlQuery(nameof(DelegationPermitted), NotDelegated, !value);
        }
    }

    public bool AllowReversiblePasswordEncryption
    {
        get => HasUserAccountControlBit(ReversiblePasswordEncryption);
        set
        {
            SetUserAccountControlBit(ReversiblePasswordEncryption, value);
            SetUserAccountControlQuery(nameof(AllowReversiblePasswordEncryption), ReversiblePasswordEncryption, value);
        }
    }

    public bool SmartcardLogonRequired
    {
        get => HasUserAccountControlBit(SmartcardRequired);
        set
        {
            SetUserAccountControlBit(SmartcardRequired, value);
            SetUserAccountControlQuery(nameof(SmartcardLogonRequired), SmartcardRequired, value);
        }
    }

    public byte[]? PermittedLogonTimes
    {
        get => GetValue("logonHours") as byte[];
        set => SetValue("logonHours", value);
    }

    public PrincipalValueCollection<string> PermittedWorkstations
    {
        get
        {
            CheckDisposedOrDeleted();
            return _permittedWorkstations ??= new PrincipalValueCollection<string>(
                ReadPermittedWorkstations(),
                values => SetPermittedWorkstations(values));
        }
    }

    public X509Certificate2Collection Certificates
    {
        get
        {
            CheckDisposedOrDeleted();
            if (_certificates is not null)
            {
                return _certificates;
            }

            _certificates = new X509Certificate2Collection();
            foreach (var raw in GetRawValues("userCertificate").OfType<byte[]>())
            {
                try
                {
                    _certificates.Add(LoadCertificate(raw));
                }
                catch (CryptographicException)
                {
                    // Microsoft skips malformed values rather than making the
                    // whole collection unreadable.
                }
            }

            _certificateThumbprints = CertificateThumbprints(_certificates);
            return _certificates;
        }
    }

    public bool UserCannotChangePassword
    {
        get
        {
            CheckDisposedOrDeleted();
            if (_userCannotChangePassword is not null)
            {
                return _userCannotChangePassword.Value;
            }

            if (Entry is null)
            {
                return false;
            }

            var descriptor = Entry.ReadSecurityDescriptorImmediate(SecurityMasks.Dacl);
            return ChangePasswordAcl.IsDenied(descriptor);
        }
        set
        {
            CheckDisposedOrDeleted();
            _userCannotChangePassword = value;
            SetQueryFilter(
                nameof(UserCannotChangePassword),
                PrincipalQueryFilterKind.Unsupported,
                string.Empty,
                value);
        }
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
        CheckDisposedOrDeleted();
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
        CheckDisposedOrDeleted();
        ArgumentNullException.ThrowIfNull(newPassword);
        if (Entry is null)
        {
            _passwordToSet = newPassword;
            var requestedEnabled = Enabled;
            if (requestedEnabled is not null)
            {
                _enabledAfterPassword = requestedEnabled.Value;
                SetUserAccountControlBit(AccountDisabled, on: true);
            }
            return;
        }

        // AD wants the password quoted and encoded as little-endian UTF-16.
        ExecuteSetPasswordOperation(() => SetPasswordImmediate(newPassword));
    }

    public void ChangePassword(string oldPassword, string newPassword)
    {
        CheckDisposedOrDeleted();
        ArgumentNullException.ThrowIfNull(oldPassword);
        ArgumentNullException.ThrowIfNull(newPassword);
        var entry = RequireSaved();
        if (this is not UserPrincipal)
        {
            throw new NotSupportedException("Changing a password is supported only for user principals.");
        }

        ExecutePasswordOperation(
            () => entry.ChangePasswordImmediate(EncodePassword(oldPassword), EncodePassword(newPassword)));
    }

    /// <summary>Unlocks a locked-out account. Takes effect immediately.</summary>
    public void UnlockAccount()
    {
        CheckDisposedOrDeleted();
        var entry = RequireSaved();
        entry.ReplaceAttributeImmediate("lockoutTime", "0");
    }

    /// <summary>Forces the password to be changed at next logon. Immediate.</summary>
    public void ExpirePasswordNow()
    {
        CheckDisposedOrDeleted();
        if (Entry is null)
        {
            _expirePasswordAfterSave = true;
            return;
        }

        Entry.ReplaceAttributeImmediate("pwdLastSet", "0");
    }

    public void RefreshExpiredPassword()
    {
        CheckDisposedOrDeleted();
        if (Entry is null)
        {
            _expirePasswordAfterSave = false;
            return;
        }

        Entry.ReplaceAttributeImmediate("pwdLastSet", "-1");
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

    private void SetUserAccountControlQuery(string property, uint bit, bool bitMustBeSet)
    {
        RemoveQueryFilter("userAccountControl");
        SetQueryFilter(
            property,
            PrincipalQueryFilterKind.UserAccountControlBit,
            "userAccountControl",
            bitMustBeSet,
            bit);
    }

    internal override IEnumerable<PrincipalQueryFilter> QueryFilters
    {
        get
        {
            foreach (var filter in base.QueryFilters)
            {
                yield return filter;
            }

            if (_certificates is { Count: > 0 })
            {
                yield return new PrincipalQueryFilter(
                    nameof(Certificates),
                    PrincipalQueryFilterKind.CertificateCollection,
                    "userCertificate",
                    _certificates.Cast<X509Certificate2>().ToArray());
            }
        }
    }

    private DirectoryEntry RequireSaved() =>
        Entry ?? throw new InvalidOperationException(
            "The account must be saved before this operation.");

    private static void ExecutePasswordOperation(Action operation)
    {
        try
        {
            operation();
        }
        catch (System.DirectoryServices.Protocols.DirectoryOperationException exception)
        {
            throw new PasswordException(exception.Message, exception);
        }
    }

    private static void ExecuteSetPasswordOperation(Action operation)
    {
        try
        {
            operation();
        }
        catch (System.DirectoryServices.Protocols.DirectoryOperationException exception)
        {
            throw new InvalidOperationException(exception.Message, exception);
        }
    }

    private void SetPasswordImmediate(string password) =>
        Entry!.ReplaceAttributeImmediate("unicodePwd", EncodePassword(password));

    private static void ExecuteDeferredPasswordOperation(Action operation)
    {
        try
        {
            operation();
        }
        catch (System.DirectoryServices.Protocols.DirectoryOperationException exception)
        {
            // Microsoft surfaces a password rejected by SetPassword as an
            // InvalidOperationException, both immediately and during Save().
            throw new InvalidOperationException(exception.Message, exception);
        }
    }

    private protected override void OnAfterSave()
    {
        base.OnAfterSave();
        if (_passwordToSet is not null)
        {
            ExecuteDeferredPasswordOperation(() => SetPasswordImmediate(_passwordToSet));
            _passwordToSet = null;
        }

        if (_expirePasswordAfterSave)
        {
            Entry!.ReplaceAttributeImmediate("pwdLastSet", "0");
            _expirePasswordAfterSave = false;
        }

        if (_enabledAfterPassword is not null)
        {
            Enabled = _enabledAfterPassword.Value;
            Entry!.CommitChanges();
            _enabledAfterPassword = null;
        }

        if (_userCannotChangePassword is not null)
        {
            var descriptor = Entry!.ReadSecurityDescriptorImmediate(SecurityMasks.Dacl);
            var changed = ChangePasswordAcl.SetDenied(descriptor, _userCannotChangePassword.Value);
            Entry.ReplaceSecurityDescriptorImmediate(changed, SecurityMasks.Dacl);
            _userCannotChangePassword = null;
        }

        if (_certificates is not null)
        {
            _certificateThumbprints = CertificateThumbprints(_certificates);
        }
    }

    private protected override void OnBeforeSave()
    {
        base.OnBeforeSave();
        if (_certificates is not null
            && !_certificateThumbprints.SequenceEqual(CertificateThumbprints(_certificates), StringComparer.OrdinalIgnoreCase))
        {
            SetValues("userCertificate", _certificates.Cast<X509Certificate2>()
                .Select(certificate => certificate.RawData)
                .ToArray());
        }
    }

    private IEnumerable<string> ReadPermittedWorkstations()
    {
        var value = GetString("userWorkstations");
        return string.IsNullOrEmpty(value) ? Array.Empty<string>() : value.Split(',');
    }

    private void SetPermittedWorkstations(IReadOnlyList<string> values)
    {
        var value = values.Count == 0 ? null : string.Join(',', values);
        SetString("userWorkstations", value);
        if (values.Count == 0)
        {
            RemoveQueryFilter("userWorkstations");
            return;
        }

        SetQueryFilter(
            "userWorkstations",
            PrincipalQueryFilterKind.Workstations,
            "userWorkstations",
            values.ToArray());
    }

    private static byte[] EncodePassword(string password) =>
        Encoding.Unicode.GetBytes('"' + password + '"');

    private static string[] CertificateThumbprints(X509Certificate2Collection certificates) =>
        certificates.Cast<X509Certificate2>()
            .Select(certificate => certificate.Thumbprint)
            .OrderBy(thumbprint => thumbprint, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static X509Certificate2 LoadCertificate(byte[] raw)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(raw);
#else
#pragma warning disable SYSLIB0057
        return new X509Certificate2(raw);
#pragma warning restore SYSLIB0057
#endif
    }

    public static PrincipalSearchResult<AuthenticablePrincipal> FindByLockoutTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, BuildDateCondition(context, "lockoutTime", time, type));
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByLogonTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, BuildLastLogonCondition(context, time, type));
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByExpirationTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, BuildDateCondition(context, "accountExpires", time, type));
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByBadPasswordAttempt(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, BuildDateCondition(context, "badPasswordTime", time, type));
    public static PrincipalSearchResult<AuthenticablePrincipal> FindByPasswordSetTime(PrincipalContext context, DateTime time, MatchType type) =>
        FindByAdvancedFilter<AuthenticablePrincipal>(context, BuildDateCondition(context, "pwdLastSet", time, type));

    protected static PrincipalSearchResult<T> FindByLockoutTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, BuildDateCondition(context, "lockoutTime", time, type));
    protected static PrincipalSearchResult<T> FindByLogonTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, BuildLastLogonCondition(context, time, type));
    protected static PrincipalSearchResult<T> FindByExpirationTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, BuildDateCondition(context, "accountExpires", time, type));
    protected static PrincipalSearchResult<T> FindByBadPasswordAttempt<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, BuildDateCondition(context, "badPasswordTime", time, type));
    protected static PrincipalSearchResult<T> FindByPasswordSetTime<T>(PrincipalContext context, DateTime time, MatchType type) where T : AuthenticablePrincipal =>
        FindByAdvancedFilter<T>(context, BuildDateCondition(context, "pwdLastSet", time, type));

    private static string BuildDateCondition(
        PrincipalContext context,
        string attribute,
        DateTime time,
        MatchType type,
        bool excludeDefaultValue = false)
    {
        ArgumentNullException.ThrowIfNull(context);
        return AdvancedFilters.ToLdapDateCondition(attribute, time, type, excludeDefaultValue);
    }

    private static string BuildLastLogonCondition(PrincipalContext context, DateTime time, MatchType type)
    {
        ArgumentNullException.ThrowIfNull(context);
        return $"(|{AdvancedFilters.ToLdapDateCondition("lastLogon", time, type)}" +
            $"{AdvancedFilters.ToLdapDateCondition("lastLogonTimestamp", time, type, requirePresenceForNotEquals: true)})";
    }

    private static PrincipalSearchResult<T> FindByAdvancedFilter<T>(PrincipalContext context, string condition)
        where T : AuthenticablePrincipal
    {
        ArgumentNullException.ThrowIfNull(context);
        var category = typeof(T) == typeof(ComputerPrincipal)
            ? "(objectCategory=computer)"
            : typeof(T) == typeof(UserPrincipal)
                ? "(objectCategory=person)(objectClass=user)"
                : "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        using var root = context.CreateDirectoryEntry(context.QueryContainer);
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
