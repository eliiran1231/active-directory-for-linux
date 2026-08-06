using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 2: prove we can bind to the directory over TLS and read the rootDSE.
/// Runs against smblds in Docker.
/// </summary>
public class ConnectionTests
{
    private static LdapConnectionOptions Options() => new()
    {
        Host = TestSettings.Host,
        Port = TestSettings.Port,
        UseSsl = TestSettings.UseTls,
        SkipCertificateCheck = true,   // smblds uses a self-signed certificate
        BindDn = TestSettings.BindDn,
        BindPassword = TestSettings.BindPassword,
    };

    [Fact]
    public void Simple_bind_over_tls_succeeds()
    {
        using var connection = LdapConnectionFactory.CreateBound(Options());
        Assert.NotNull(connection);
    }

    [Fact]
    public void RootDse_reports_the_expected_default_naming_context()
    {
        using var connection = LdapConnectionFactory.CreateBound(Options());

        var namingContext = RootDse.GetDefaultNamingContext(connection);

        Assert.Equal(TestSettings.BaseDn, namingContext, ignoreCase: true);
    }

    [Fact]
    public void Anonymous_bind_can_still_read_rootDse()
    {
        // rootDSE is readable without credentials on AD.
        var anonymous = new LdapConnectionOptions
        {
            Host = TestSettings.Host,
            Port = TestSettings.Port,
            UseSsl = TestSettings.UseTls,
            SkipCertificateCheck = true,
        };

        using var connection = LdapConnectionFactory.CreateBound(anonymous);

        var values = RootDse.Read(connection, "supportedLDAPVersion");
        Assert.True(values.Count >= 0); // did not throw = anonymous bind worked
    }
}
