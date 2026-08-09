namespace AdForLinux.DifferentialTests;

/// <summary>
/// Connection settings, read from environment variables. The same names the
/// Linux functional tests use, so one set of variables drives both.
/// </summary>
public static class DifferentialSettings
{
    public static string Host =>
        Environment.GetEnvironmentVariable("AD_HOST") ?? "localhost";

    public static int Port =>
        int.TryParse(Environment.GetEnvironmentVariable("AD_PORT"), out var p) ? p : 636;

    public static bool UseTls =>
        (Environment.GetEnvironmentVariable("AD_USE_TLS") ?? "true")
            .Equals("true", StringComparison.OrdinalIgnoreCase);

    public static string BindDn =>
        Environment.GetEnvironmentVariable("AD_BIND_DN") ?? "administrator@samdom.example.com";

    public static string BindPassword =>
        Environment.GetEnvironmentVariable("AD_BIND_PW") ?? "Passw0rd";

    public static string BaseDn =>
        Environment.GetEnvironmentVariable("AD_BASE_DN") ?? "DC=samdom,DC=example,DC=com";

    /// <summary>Where the tests create their temporary objects.</summary>
    public static string UsersContainer => $"CN=Users,{BaseDn}";

    /// <summary>Server in <c>host:port</c> form, for PrincipalContext.</summary>
    public static string ServerName => $"{Host}:{Port}";

    /// <summary>An LDAP path for a DN on the test server.</summary>
    public static string PathFor(string distinguishedName) =>
        $"LDAP://{Host}:{Port}/{distinguishedName}";
}
