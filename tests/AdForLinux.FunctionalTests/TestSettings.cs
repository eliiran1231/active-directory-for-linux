namespace AdForLinux.FunctionalTests;

/// <summary>
/// Test connection settings, read from environment variables so the same
/// tests can point at smblds locally or a real Windows AD later.
/// </summary>
public static class TestSettings
{
    public static string Host =>
        Environment.GetEnvironmentVariable("AD_HOST") ?? "host.docker.internal";

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
}
