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

    public static System.DirectoryServices.AccountManagement.ContextOptions MicrosoftContextOptions =>
        UseTls
            ? System.DirectoryServices.AccountManagement.ContextOptions.SimpleBind |
              System.DirectoryServices.AccountManagement.ContextOptions.SecureSocketLayer
            : System.DirectoryServices.AccountManagement.ContextOptions.Negotiate |
              System.DirectoryServices.AccountManagement.ContextOptions.Signing |
              System.DirectoryServices.AccountManagement.ContextOptions.Sealing;

    public static AdForLinux.DirectoryServices.AccountManagement.ContextOptions OurContextOptions =>
        UseTls
            ? AdForLinux.DirectoryServices.AccountManagement.ContextOptions.SimpleBind |
              AdForLinux.DirectoryServices.AccountManagement.ContextOptions.SecureSocketLayer
            : AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Negotiate |
              AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Signing |
              AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Sealing;

    public static System.DirectoryServices.AuthenticationTypes MicrosoftAuthenticationTypes =>
        UseTls
            ? System.DirectoryServices.AuthenticationTypes.SecureSocketsLayer
            : System.DirectoryServices.AuthenticationTypes.Secure |
              System.DirectoryServices.AuthenticationTypes.Signing |
              System.DirectoryServices.AuthenticationTypes.Sealing;

    public static AdForLinux.DirectoryServices.AuthenticationTypes OurAuthenticationTypes =>
        UseTls
            ? AdForLinux.DirectoryServices.AuthenticationTypes.SecureSocketsLayer
            : AdForLinux.DirectoryServices.AuthenticationTypes.Secure |
              AdForLinux.DirectoryServices.AuthenticationTypes.Signing |
              AdForLinux.DirectoryServices.AuthenticationTypes.Sealing;

    /// <summary>An LDAP path for a DN on the test server.</summary>
    public static string PathFor(string distinguishedName) =>
        $"LDAP://{Host}:{Port}/{distinguishedName}";
}
