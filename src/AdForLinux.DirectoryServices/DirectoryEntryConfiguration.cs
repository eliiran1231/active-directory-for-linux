namespace AdForLinux.DirectoryServices;

/// <summary>Provider-style LDAP options exposed by <see cref="DirectoryEntry.Options"/>.</summary>
public sealed class DirectoryEntryConfiguration
{
    private readonly DirectoryEntry _entry;

    internal DirectoryEntryConfiguration(DirectoryEntry entry) => _entry = entry;

    /// <summary>Gets or sets the preferred page size for provider operations.</summary>
    public int PageSize { get; set; }

    /// <summary>Gets or sets how passwords are encoded for password changes.</summary>
    public PasswordEncodingMethod PasswordEncoding { get; set; } = PasswordEncodingMethod.PasswordEncodingSsl;

    /// <summary>Gets or sets the port used for password operations.</summary>
    public int PasswordPort { get; set; } = 636;

    /// <summary>Gets or sets the referral-chasing preference.</summary>
    public ReferralChasingOption Referral { get; set; } = ReferralChasingOption.External;

    /// <summary>Gets or sets the requested security descriptor parts.</summary>
    public SecurityMasks SecurityMasks { get; set; }

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
