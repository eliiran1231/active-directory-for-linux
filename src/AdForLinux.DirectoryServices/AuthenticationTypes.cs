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

    /// <summary>Use secure authentication through the platform negotiation provider.</summary>
    Secure = 0x1,

    /// <summary>Use SSL/TLS to encrypt the LDAP transport.</summary>
    Encryption = 0x2,

    /// <summary>Bind to a specific server (no serverless locate). Always true here.</summary>
    ServerBind = 0x200,

    /// <summary>Use TLS (LDAPS). This is an alias for <see cref="Encryption"/>.</summary>
    SecureSocketsLayer = 0x2,

    /// <summary>ADSI fast bind. LDAP Protocols has no faithful equivalent.</summary>
    FastBind = 0x20,

    /// <summary>Read-only server selection hint.</summary>
    ReadonlyServer = 0x4,

    /// <summary>Request delegated secure authentication.</summary>
    Delegation = 0x100,

    /// <summary>Request SASL sealing. Requires <see cref="Secure"/>.</summary>
    Sealing = 0x80,

    /// <summary>Request SASL signing. Requires <see cref="Secure"/>.</summary>
    Signing = 0x40,
}
