using AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Test connection settings, read from environment variables so the same
/// tests can point at smblds locally or a real Windows AD later.
/// </summary>
public static class TestSettings
{
    private static string? ReadLiveSetting(string name)
    {
        AdForLinux.DirectoryServices.Ldap.OfflineTestGuard.RequireLiveAccess();
        return Environment.GetEnvironmentVariable(name);
    }

    public static string Host =>
        ReadLiveSetting("AD_HOST") ?? "host.docker.internal";

    public static int Port =>
        int.TryParse(ReadLiveSetting("AD_PORT"), out var p) ? p : 636;

    public static bool UseTls =>
        (ReadLiveSetting("AD_USE_TLS") ?? "true")
            .Equals("true", StringComparison.OrdinalIgnoreCase);

    public static string BindDn =>
        ReadLiveSetting("AD_BIND_DN") ?? "administrator@samdom.example.com";

    public static string BindPassword =>
        ReadLiveSetting("AD_BIND_PW") ?? "Passw0rd";

    public static string BaseDn =>
        ReadLiveSetting("AD_BASE_DN") ?? "DC=samdom,DC=example,DC=com";

    /// <summary>Server name in <c>host:port</c> form, for PrincipalContext.</summary>
    public static string ServerName => $"{Host}:{Port}";

    /// <summary>Explicit bind options used by the Samba-backed fixtures.</summary>
    public static ContextOptions PrincipalContextOptions =>
        ContextOptions.SimpleBind |
        (UseTls ? ContextOptions.SecureSocketLayer : 0);

    /// <summary>Creates a live test context without relying on public defaults.</summary>
    public static PrincipalContext CreatePrincipalContext(string? container = null) =>
        new(
            ContextType.Domain,
            ServerName,
            container,
            PrincipalContextOptions,
            BindDn,
            BindPassword);

    /// <summary>Well-known DN of the built-in Administrator account.</summary>
    public static string AdministratorDn => $"CN=Administrator,CN=Users,{BaseDn}";

    /// <summary>Builds an LDAP path for a DN, using the test host and port.</summary>
    public static string PathFor(string distinguishedName) =>
        $"LDAP://{Host}:{Port}/{distinguishedName}";
}
