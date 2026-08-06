namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// How a <see cref="PrincipalContext"/> connects and binds. Values match
/// Microsoft so existing code keeps working.
///
/// This Linux port always binds simply over TLS. So <see cref="Negotiate"/> is
/// accepted but treated like a simple bind, and <see cref="SecureSocketLayer"/>
/// is on by default (the port would otherwise refuse a simple bind).
/// </summary>
[Flags]
public enum ContextOptions
{
    /// <summary>Negotiate (Kerberos/NTLM) on Windows. Falls back to simple bind here.</summary>
    Negotiate = 1,

    /// <summary>Simple bind (username + password). The only bind this port does.</summary>
    SimpleBind = 2,

    /// <summary>Sign the traffic. Accepted and ignored (TLS already protects it).</summary>
    Signing = 16,

    /// <summary>Seal (encrypt) the traffic. Accepted; TLS already encrypts.</summary>
    Sealing = 32,

    /// <summary>Use TLS (LDAPS). On by default in this port.</summary>
    SecureSocketLayer = 4,

    /// <summary>Bind to a specific server. Always true here.</summary>
    ServerBind = 512,
}
