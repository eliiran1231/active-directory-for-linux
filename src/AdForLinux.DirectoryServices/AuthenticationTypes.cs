namespace AdForLinux.DirectoryServices;

/// <summary>
/// Bind options for <see cref="DirectoryEntry"/>. A subset of Microsoft's enum,
/// with the flags that matter for a Linux LDAP client. Values match Microsoft's
/// so existing code that passes them keeps working.
/// </summary>
[Flags]
public enum AuthenticationTypes
{
    /// <summary>No special options.</summary>
    None = 0,

    /// <summary>Use an anonymous bind.</summary>
    Anonymous = 0x10,

    /// <summary>Request signing/encryption. Mapped to a TLS bind here.</summary>
    Secure = 0x1,

    /// <summary>Request encryption. Mapped to TLS by this LDAP implementation.</summary>
    Encryption = 0x2,

    /// <summary>Bind to a specific server (no serverless locate). Always true here.</summary>
    ServerBind = 0x200,

    /// <summary>Use TLS (LDAPS). This is the flag that turns on encryption.</summary>
    SecureSocketsLayer = 0x2,

    /// <summary>ADSI fast bind. LDAP has no equivalent and the flag is accepted as a hint.</summary>
    FastBind = 0x20,

    /// <summary>Read-only server hint. Accepted and ignored.</summary>
    ReadonlyServer = 0x4,

    /// <summary>Delegation hint. Accepted and ignored.</summary>
    Delegation = 0x100,

    /// <summary>Sealing hint. Accepted and ignored.</summary>
    Sealing = 0x80,

    /// <summary>Signing hint. Accepted and ignored.</summary>
    Signing = 0x40,
}
