namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// How a <see cref="PrincipalContext"/> connects and binds. Values match
/// Microsoft so existing code keeps working.
/// </summary>
[Flags]
public enum ContextOptions
{
    /// <summary>Use LDAP negotiate authentication (Kerberos/NTLM).</summary>
    Negotiate = 1,

    /// <summary>Use an LDAP simple bind (username + password).</summary>
    SimpleBind = 2,

    /// <summary>Request LDAP signing for negotiate authentication.</summary>
    Signing = 8,

    /// <summary>Request LDAP sealing for negotiate authentication.</summary>
    Sealing = 16,

    /// <summary>Use TLS (LDAPS).</summary>
    SecureSocketLayer = 4,

    /// <summary>Bind to a specific server. Always true here.</summary>
    ServerBind = 32,
}
