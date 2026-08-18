using System.ComponentModel;

namespace AdForLinux.DirectoryServices;

/// <summary>Provider-style LDAP options exposed by <see cref="DirectoryEntry.Options"/>.</summary>
public sealed class DirectoryEntryConfiguration
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
    /// Gets or sets how passwords are encoded for password changes. Portable LDAP password
    /// operations support only SSL encoding; clear-text password encoding is rejected.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// The requested encoding is <see cref="PasswordEncodingMethod.PasswordEncodingClear"/>.
    /// </exception>
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

            if (value == PasswordEncodingMethod.PasswordEncodingClear)
            {
                throw new PlatformNotSupportedException(
                    "Clear-text password encoding is not supported. Password operations require an SSL-protected LDAP connection.");
            }

            _passwordEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets the port used for password operations. Portable LDAP password operations
    /// use the entry's existing SSL connection, so only the standard LDAPS port 636 is supported.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">The requested port is not 636.</exception>
    public int PasswordPort
    {
        get => _passwordPort;
        set
        {
            if (value != 636)
            {
                throw new PlatformNotSupportedException(
                    "A separate password-operation port is not supported. Use the entry's SSL connection on port 636.");
            }

            _passwordPort = value;
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

    /// <summary>Gets the connected LDAP server name.</summary>
    public string GetCurrentServerName() => _entry.ServerHost
        ?? throw new InvalidOperationException("A server must be present in the LDAP path.");

    /// <summary>Returns false because this implementation uses LDAP simple bind rather than an ADSI mutual-authentication provider.</summary>
    public bool IsMutuallyAuthenticated() => false;

    /// <summary>ADSI-specific user-name quota configuration is not available over LDAP.</summary>
    public void SetUserNameQueryQuota(string userName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
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
