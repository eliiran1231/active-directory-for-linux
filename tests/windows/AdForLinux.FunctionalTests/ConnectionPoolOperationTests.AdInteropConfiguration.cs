using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.IntegrationTests;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private static AdKerberosConfiguration AdReadConfiguration() => new(
        Path.GetFullPath("recording-bundle"), "EXAMPLE.INVALID", "dc.invalid", 389,
        "kdc.invalid", 88, "/recording/a.ccache", "/recording/b.ccache",
        "dc=example,dc=invalid", "(description=pool-*)", "description", "pool-a", "pool-b",
        ["cn=a1,dc=example,dc=invalid", "cn=a2,dc=example,dc=invalid"],
        ["cn=b1,dc=example,dc=invalid", "cn=b2,dc=example,dc=invalid"]);

    [Fact]
    public void Ad_interop_configuration_selects_owned_Negotiate_and_never_Basic()
    {
        var configuration = AdReadConfiguration(); configuration.Validate();
        using var owner = new KerberosCredentialContext([1]);
        using var entry = configuration.Profile(owner).CreateDirectoryEntry(configuration.SearchBaseDn);
        var options = entry.BuildOptions();
        Assert.Equal(System.DirectoryServices.Protocols.AuthType.Negotiate, options.AuthenticationType);
        Assert.True(options.Signing); Assert.True(options.Sealing); Assert.False(options.UseSsl);
        Assert.Same(owner, options.RestrictedKerberos!.OwnedCredentials);
        Assert.Throws<InvalidOperationException>(() => configuration.Profile(owner).ValidateRecipe(new LdapConnectionOptions
        { Host = configuration.ServiceHost, Port = 389, UseSsl = false,
            AuthenticationType = System.DirectoryServices.Protocols.AuthType.Basic }));
    }

    [Fact]
    public void Ad_interop_configuration_requires_disjoint_identity_proofs_and_explicit_sources()
    {
        var valid = AdReadConfiguration();
        Assert.Throws<ArgumentException>(() => (valid with { CacheB = valid.CacheA }).Validate());
        Assert.Throws<ArgumentException>(() => (valid with { CacheB = "C:\\recording\\b.ccache" }).Validate());
        Assert.Throws<ArgumentException>(() => (valid with { ExpectedDnsB = valid.ExpectedDnsA }).Validate());
        Assert.Throws<ArgumentException>(() => (valid with { ExpectedDnsB = ["cn=b"] }).Validate());
        Assert.Throws<ArgumentException>(() => (valid with { MarkerValueB = valid.MarkerValueA }).Validate());
        Assert.Throws<ArgumentException>(() => (valid with { MarkerAttribute = "description)(objectClass=*" }).Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => (valid with { ServicePort = 636 }).Validate());
    }
}
