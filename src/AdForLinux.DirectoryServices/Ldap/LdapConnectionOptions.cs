using System.Net;
using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Everything needed to open one LDAP connection to a directory server.
/// Shared by the low layer (DirectoryEntry) and the high layer
/// (PrincipalContext).
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

    /// <summary>The LDAP authentication mechanism used for the bind.</summary>
    public AuthType AuthenticationType { get; init; } = AuthType.Basic;

    /// <summary>Whether SASL signing is requested for the connection.</summary>
    public bool Signing { get; init; }

    /// <summary>Whether SASL sealing is requested for the connection.</summary>
    public bool Sealing { get; init; }

    /// <summary>
    /// Bind user. A UPN (user@domain), a DOMAIN\user, or a full DN.
    /// Null or empty means an anonymous (unauthenticated) bind.
    /// </summary>
    public string? BindDn { get; init; }

    /// <summary>Bind password. Ignored for anonymous bind.</summary>
    public string? BindPassword { get; init; }

    /// <summary>True when a Basic bind has no username, or Anonymous was requested explicitly.</summary>
    public bool IsAnonymous =>
        AuthenticationType == AuthType.Anonymous ||
        (AuthenticationType == AuthType.Basic && string.IsNullOrEmpty(BindDn));

    /// <summary>Builds the explicit credential, or null to use anonymous/default credentials.</summary>
    public NetworkCredential? ToCredential() =>
        IsAnonymous || string.IsNullOrEmpty(BindDn)
            ? null
            : new NetworkCredential(BindDn, BindPassword);
}
