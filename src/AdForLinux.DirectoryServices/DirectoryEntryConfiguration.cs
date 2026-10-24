using System.ComponentModel;

namespace AdForLinux.DirectoryServices;

/// <summary>Provider-style LDAP options exposed by <see cref="DirectoryEntry.Options"/>.</summary>
public class DirectoryEntryConfiguration
{
    private readonly DirectoryEntry _entry;
    private int _pageSize;
    private PasswordEncodingMethod _passwordEncoding;
    private int _passwordPort;
    private ReferralChasingOption _referral;
    private SecurityMasks _securityMasks;

    // ADS_SECURITY_INFO_ENUM documents Owner, Group and DACL as the initial mask.
    // https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_security_info_enum
    internal const SecurityMasks DefaultSecurityMasks =
        SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl;

    internal DirectoryEntryConfiguration(DirectoryEntry entry)
    {
        _entry = entry;
        Reset();
    }

    private volatile bool _revoked;
    internal void Revoke() => _revoked = true;
    internal void ValidateOwner()
    {
        if (_revoked) throw new InvalidOperationException("This configuration belongs to a revoked entry binding.");
        _entry.ThrowIfDisposed();
    }

    internal void Reset()
    {
        // Reset this wrapper in place: callers may retain it across Close().
        // The documented portable default disables paging. ADSI's provider
        // default is intentionally not part of this contract (see README).
        _pageSize = 0;
        _securityMasks = DefaultSecurityMasks;
        _passwordEncoding = PasswordEncodingMethod.PasswordEncodingSsl;
        _passwordPort = 636;
        _referral = ReferralChasingOption.External;
    }

    /// <summary>Gets or sets the page size used when enumerating child entries. Zero disables paging.</summary>
    public int PageSize
    {
        get { ValidateOwner(); return _pageSize; }
        set
        {
            if (value < 0)
            {
                throw new ArgumentException("The PageSize must be greater than or equal to zero.");
            }

            ValidateOwner();
            _pageSize = value;
        }
    }

    /// <summary>
    /// Gets or sets the requested password encoding. Both defined values are stored for
    /// compatibility; password operations reject clear-text encoding when invoked.
    /// </summary>
    public PasswordEncodingMethod PasswordEncoding
    {
        get { ValidateOwner(); return _passwordEncoding; }
        set
        {
            if (value is not PasswordEncodingMethod.PasswordEncodingSsl and
                not PasswordEncodingMethod.PasswordEncodingClear)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(PasswordEncodingMethod));
            }

            ValidateOwner();
            _passwordEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets the requested password-operation port. Values are stored for compatibility;
    /// password operations reject nondefault ports because separate password connections are unsupported.
    /// </summary>
    public int PasswordPort
    {
        get { ValidateOwner(); return _passwordPort; }
        set { ValidateOwner(); _passwordPort = value; }
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
        get { ValidateOwner(); return _referral; }
        set
        {
            if (value is not ReferralChasingOption.None and
                not ReferralChasingOption.Subordinate and
                not ReferralChasingOption.External and
                not ReferralChasingOption.All)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(ReferralChasingOption));
            }

            ValidateOwner();
            if (_referral != value)
            {
                _entry.OnReferralChanged(this, () => _referral = value);
            }
        }
    }

    /// <summary>
    /// Gets or sets the requested security descriptor parts. A fresh binding
    /// requests the owner, group and DACL; reading the SACL requires an explicit flag.
    /// </summary>
    public SecurityMasks SecurityMasks
    {
        get { ValidateOwner(); return _securityMasks; }
        set
        {
            const SecurityMasks allMasks = SecurityMasks.Owner | SecurityMasks.Group |
                                           SecurityMasks.Dacl | SecurityMasks.Sacl;
            if (value < SecurityMasks.None || value > allMasks)
            {
                throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(SecurityMasks));
            }

            ValidateOwner();
            _securityMasks = value;
        }
    }

    /// <summary>Gets the server backing the entry's active LDAP connection.</summary>
    public string GetCurrentServerName()
    {
        ValidateOwner();
        using var lease = _entry.AcquireConfigurationConnection(this);
        return Ldap.RootDse.GetConnectedServerName(lease.Connection);
    }

    /// <summary>
    /// Determines whether the active LDAP authentication exchanged mutual credentials.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// <c>System.DirectoryServices.Protocols</c> does not expose the negotiated mutual-
    /// authentication status of an LDAP bind.
    /// </exception>
    public bool IsMutuallyAuthenticated()
    {
        ValidateOwner();
        // Bind first so this member cannot make an invalid configured endpoint
        // appear healthy merely because the protocol limitation is known.
        using var lease = _entry.AcquireConfigurationConnection(this);
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
