using System.Net;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Everything needed to open one LDAP connection to a directory server.
/// Shared by the low layer (DirectoryEntry) and the high layer
/// (PrincipalContext). Simple bind over TLS only, for now.
/// </summary>
internal sealed class LdapConnectionOptions
{
    /// <summary>Server host name or IP.</summary>
    public required string Host { get; init; }

    /// <summary>Port. 636 for LDAPS, 389 for plain/StartTLS.</summary>
    public int Port { get; init; } = 636;

    /// <summary>Wrap the whole connection in TLS (LDAPS). Use with port 636.</summary>
    public bool UseSsl { get; init; } = true;

    /// <summary>Upgrade a plain connection to TLS with StartTLS. Use with port 389.</summary>
    public bool UseStartTls { get; init; }

    /// <summary>
    /// Skip TLS certificate checks. Needed for the self-signed smblds cert.
    /// Do not use this against real AD in production.
    /// </summary>
    public bool SkipCertificateCheck { get; init; }

    /// <summary>
    /// Bind user. A UPN (user@domain), a DOMAIN\user, or a full DN.
    /// Null or empty means an anonymous (unauthenticated) bind.
    /// </summary>
    public string? BindDn { get; init; }

    /// <summary>Bind password. Ignored for anonymous bind.</summary>
    public string? BindPassword { get; init; }

    /// <summary>True when no bind user was given.</summary>
    public bool IsAnonymous => string.IsNullOrEmpty(BindDn);

    /// <summary>Builds the credential for a simple bind, or null when anonymous.</summary>
    public NetworkCredential? ToCredential() =>
        IsAnonymous ? null : new NetworkCredential(BindDn, BindPassword);
}
