using System.ComponentModel;

namespace AdForLinux.DirectoryServices;

/// <summary>Provider-style LDAP options exposed by <see cref="DirectoryEntry.Options"/>.</summary>
public class DirectoryEntryConfiguration
{
    private readonly DirectoryEntry _entry;
    private int _pageSize;
    private PasswordEncodingMethod _passwordEncoding = PasswordEncodingMethod.PasswordEncodingSsl;
    private int _passwordPort = 636;
    private ReferralChasingOption _referral = ReferralChasingOption.External;
    private SecurityMasks _securityMasks;

    internal DirectoryEntryConfiguration(DirectoryEntry entry) => _entry = entry;

    /// <summary>Gets or sets the page size used when enumerating child entries. Zero disables paging.</summary>
    public int PageSize
    {
        get => _pageSize;
        set
        {
            if (value < 0)
            {
                throw new ArgumentException("The PageSize must be greater than or equal to zero.", nameof(value));
            }

            _pageSize = value;
        }
    }

    /// <summary>
    /// Gets or sets the requested password encoding. Both defined values are stored for
    /// compatibility; password operations reject clear-text encoding when invoked.
    /// </summary>
    public PasswordEncodingMethod PasswordEncoding
    {
        get => _passwordEncoding;
        set
        {
            if (value is not PasswordEncodingMethod.PasswordEncodingSsl and
                not PasswordEncodingMethod.PasswordEncodingClear)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(PasswordEncodingMethod));
            }

            _passwordEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets the requested password-operation port. Values are stored for compatibility;
    /// password operations reject nondefault ports because separate password connections are unsupported.
    /// </summary>
    public int PasswordPort
    {
        get => _passwordPort;
        set => _passwordPort = value;
    }

    internal void ValidatePasswordOperation()
    {
        if (_passwordEncoding == PasswordEncodingMethod.PasswordEncodingClear)
        {
            throw new PlatformNotSupportedException(
                "Clear-text password encoding is not supported. Password operations require an SSL-protected LDAP connection.");
        }

        if (_passwordPort != 636)
        {
            throw new PlatformNotSupportedException(
                "A separate password-operation port is not supported. PasswordPort must be 636 for password operations.");
        }
    }

    /// <summary>Gets or sets the referral-chasing preference.</summary>
    public ReferralChasingOption Referral
    {
        get => _referral;
        set
        {
            if (value is not ReferralChasingOption.None and
                not ReferralChasingOption.Subordinate and
                not ReferralChasingOption.External and
                not ReferralChasingOption.All)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ReferralChasingOption));
            }

            if (_referral != value)
            {
                _referral = value;
                _entry.OnReferralChanged();
            }
        }
    }

    /// <summary>Gets or sets the requested security descriptor parts.</summary>
    public SecurityMasks SecurityMasks
    {
        get => _securityMasks;
        set
        {
            const SecurityMasks allMasks = SecurityMasks.Owner | SecurityMasks.Group |
                                           SecurityMasks.Dacl | SecurityMasks.Sacl;
            if (value < SecurityMasks.None || value > allMasks)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(SecurityMasks));
            }

            _securityMasks = value;
        }
    }

    /// <summary>Gets the server backing the entry's active LDAP connection.</summary>
    public string GetCurrentServerName() =>
        Ldap.RootDse.GetConnectedServerName(_entry.GetConnection());

    /// <summary>
    /// Determines whether the active LDAP authentication exchanged mutual credentials.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// <c>System.DirectoryServices.Protocols</c> does not expose the negotiated mutual-
    /// authentication status of an LDAP bind.
    /// </exception>
    public bool IsMutuallyAuthenticated()
    {
        // Bind first so this member cannot make an invalid configured endpoint
        // appear healthy merely because the protocol limitation is known.
        _entry.GetConnection();
        throw new PlatformNotSupportedException(
            "System.DirectoryServices.Protocols does not expose whether the current LDAP bind negotiated mutual authentication.");
    }

    /// <summary>ADSI-specific user-name quota configuration is not available over LDAP.</summary>
    public void SetUserNameQueryQuota(string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        throw new PlatformNotSupportedException("SetUserNameQueryQuota requires ADSI and is not available over LDAP.");
    }
}

/// <summary>Specifies password transport encoding.</summary>
public enum PasswordEncodingMethod
{
    PasswordEncodingSsl = 0,
    PasswordEncodingClear = 1,
}

/// <summary>Specifies how LDAP referrals are chased.</summary>
public enum ReferralChasingOption
{
    None = 0,
    Subordinate = 0x20,
    External = 0x40,
    All = Subordinate | External,
}

/// <summary>Specifies requested security descriptor portions.</summary>
[Flags]
public enum SecurityMasks
{
    None = 0,
    Owner = 1,
    Group = 2,
    Dacl = 4,
    Sacl = 8,
}
