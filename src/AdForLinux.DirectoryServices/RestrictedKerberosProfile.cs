using AdForLinux.DirectoryServices.Ldap;
using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// Explicit opt-in to an isolated Linux Kerberos recipe. Construction performs
/// syntax validation only; it does not inspect caches, install bundles or bind.
/// Operations require an admitted private source-only deployment; unsupported
/// configurations fail before credential access, without ambient fallback.
/// </summary>
public sealed class RestrictedKerberosProfile
{
    public string DeploymentDirectory { get; }
    public string CredentialCacheFile { get; }
    public string Realm { get; }
    public string ServiceHost { get; }
    public int ServicePort { get; }
    public string KdcHost { get; }
    public int KdcPort { get; }

    /// <summary>
    /// Selects an administrator-managed immutable bundle and explicit FILE cache,
    /// exact LDAP target and single-realm KDC. Signing and sealing are required;
    /// TLS, referrals and cross-operation reuse are not selected by this profile.
    /// No host Kerberos configuration is imported.
    /// </summary>
    public RestrictedKerberosProfile(string deploymentDirectory, string credentialCacheFile,
        string realm, string serviceHost, int servicePort, string kdcHost, int kdcPort = 88)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentDirectory);
        if (!Path.IsPathFullyQualified(deploymentDirectory) || deploymentDirectory == "/" ||
            deploymentDirectory != Path.GetFullPath(deploymentDirectory) || deploymentDirectory.EndsWith('/') ||
            deploymentDirectory.Contains('\0'))
            throw new ArgumentException("Use a canonical absolute immutable version directory.", nameof(deploymentDirectory));
        new LdapCredentialSource(LdapCredentialSourceKind.File, credentialCacheFile).Validate();
        if (servicePort is < 1 or > 65535 || servicePort == 636)
            throw new ArgumentOutOfRangeException(nameof(servicePort), "The restricted profile requires a non-LDAPS endpoint.");
        DeploymentDirectory = deploymentDirectory; CredentialCacheFile = credentialCacheFile;
        Realm = realm; ServiceHost = serviceHost; ServicePort = servicePort; KdcHost = kdcHost; KdcPort = kdcPort;
        _ = WorkerProfile(1, TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Creates an inert entry carrying this explicit selection. Descendants retain
    /// the selection. Operations use fresh isolated worker groups only after
    /// deployment and policy admission; ambient credentials are never substituted.
    /// </summary>
    public DirectoryEntry CreateDirectoryEntry(string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(distinguishedName);
        return new DirectoryEntry(new LdapPath(ServiceHost, ServicePort, distinguishedName).ToString(), Options());
    }

    internal LdapConnectionOptions Options() => new()
    {
        Host = ServiceHost, Port = ServicePort, UseSsl = false,
        AuthenticationType = AuthType.Negotiate, Signing = true, Sealing = true, RestrictedKerberos = this
    };

    internal LdapWorkerStart WorkerProfile(int count, TimeSpan timeout)
    {
        // Module loading is unavailable in the reviewed private MIT build. This
        // fixed reserved path is configuration syntax, not a host plugin import.
        var start = new LdapWorkerStart(ServiceHost, ServicePort, false, true, true, count, timeout,
            new(LdapCredentialSourceKind.File, CredentialCacheFile),
            new(Realm, ServiceHost, "/adfl-disabled-plugins", new(KdcHost, KdcPort)));
        LdapWorkerKerberosProfile.RequireProductionPolicy(start);
        return start;
    }

    internal void ValidateRecipe(LdapConnectionOptions options)
    {
        if (!string.Equals(options.Host, ServiceHost, StringComparison.OrdinalIgnoreCase) || options.Port != ServicePort ||
            options.UseSsl || options.UseStartTls || options.SkipCertificateCheck ||
            options.AuthenticationType != AuthType.Negotiate || !options.Signing || !options.Sealing ||
            options.BindDn is not null || options.BindPassword is not null)
            throw new InvalidOperationException("The operation changes the explicitly selected restricted Kerberos recipe. Create a new profile instead.");
        _ = WorkerProfile(1, options.Timeout);
    }

    internal void RefuseUnavailableBackend(LdapConnectionOptions options)
    {
        ValidateRecipe(options);
        throw new PlatformNotSupportedException("This operation requires a raw platform connection or alternate credential validation, which the restricted worker transport cannot provide. No ambient fallback or credential access was attempted.");
    }
}
