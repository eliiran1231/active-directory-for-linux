using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using System.DirectoryServices.Protocols;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryAuthenticationTests
{
    private const string Path = "LDAP://dc.example.test/DC=example,DC=test";

    [Fact]
    public void Credential_constructor_defaults_to_secure_negotiate_authentication()
    {
        using var entry = new DirectoryEntry(Path, "user@example.test", "password");

        var options = entry.BuildOptions();

        Assert.Equal(AuthenticationTypes.Secure, entry.AuthenticationType);
        Assert.Equal(AuthType.Negotiate, options.AuthenticationType);
        Assert.False(options.UseSsl);
        Assert.False(options.Signing);
        Assert.False(options.Sealing);
    }

    [Theory]
    [InlineData(AuthenticationTypes.None, AuthType.Basic, false, false, false)]
    [InlineData(AuthenticationTypes.Secure, AuthType.Negotiate, false, false, false)]
    [InlineData(AuthenticationTypes.Secure | AuthenticationTypes.Signing, AuthType.Negotiate, false, true, false)]
    [InlineData(AuthenticationTypes.Secure | AuthenticationTypes.Sealing, AuthType.Negotiate, false, false, true)]
    [InlineData(AuthenticationTypes.SecureSocketsLayer, AuthType.Basic, true, false, false)]
    [InlineData(AuthenticationTypes.Anonymous, AuthType.Anonymous, false, false, false)]
    public void Authentication_types_map_explicitly_to_protocol_options(
        AuthenticationTypes authenticationTypes,
        AuthType expectedAuthType,
        bool expectedSsl,
        bool expectedSigning,
        bool expectedSealing)
    {
        using var entry = new DirectoryEntry(Path, "user@example.test", "password", authenticationTypes);

        var options = entry.BuildOptions();

        Assert.Equal(expectedAuthType, options.AuthenticationType);
        Assert.Equal(expectedSsl, options.UseSsl);
        Assert.Equal(expectedSigning, options.Signing);
        Assert.Equal(expectedSealing, options.Sealing);
    }

    [Fact]
    public void Explicit_anonymous_authentication_does_not_create_a_credential()
    {
        using var entry = new DirectoryEntry(
            Path,
            "must-not-be-sent@example.test",
            "must-not-be-sent",
            AuthenticationTypes.Anonymous);

        var options = entry.BuildOptions();

        Assert.True(options.IsAnonymous);
        Assert.Null(options.ToCredential());
    }

    [Fact]
    public void Children_add_clones_the_complete_negotiate_connection_configuration()
    {
        var parentOptions = new LdapConnectionOptions
        {
            Host = "dc.example.test",
            Port = 1389,
            UseSsl = false,
            UseStartTls = true,
            SkipCertificateCheck = true,
            AuthenticationType = AuthType.Negotiate,
            Signing = true,
            Sealing = true,
            BindDn = "user@example.test",
            BindPassword = "password",
            Timeout = TimeSpan.FromSeconds(17),
        };
        using var parent = new DirectoryEntry(Path, parentOptions);

        using var child = parent.Children.Add("CN=issue-56", "user");
        var childOptions = child.BuildOptions();

        Assert.NotSame(parentOptions, childOptions);
        Assert.Equal(parentOptions.Host, childOptions.Host);
        Assert.Equal(parentOptions.Port, childOptions.Port);
        Assert.Equal(parentOptions.UseSsl, childOptions.UseSsl);
        Assert.Equal(parentOptions.UseStartTls, childOptions.UseStartTls);
        Assert.Equal(parentOptions.SkipCertificateCheck, childOptions.SkipCertificateCheck);
        Assert.Equal(AuthType.Negotiate, childOptions.AuthenticationType);
        Assert.True(childOptions.Signing);
        Assert.True(childOptions.Sealing);
        Assert.Equal(parentOptions.BindDn, childOptions.BindDn);
        Assert.Equal(parentOptions.BindPassword, childOptions.BindPassword);
        Assert.Equal(parentOptions.Timeout, childOptions.Timeout);
        Assert.Equal(
            AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing,
            child.AuthenticationType);
    }

    [Theory]
    [InlineData(AuthenticationTypes.Signing)]
    [InlineData(AuthenticationTypes.Sealing)]
    [InlineData(AuthenticationTypes.Secure | AuthenticationTypes.Anonymous)]
    [InlineData(AuthenticationTypes.FastBind)]
    [InlineData(AuthenticationTypes.ReadonlyServer)]
    [InlineData(AuthenticationTypes.Delegation)]
    public void Unsupported_authentication_combinations_fail_explicitly(AuthenticationTypes authenticationTypes)
    {
        using var entry = new DirectoryEntry(Path, "user@example.test", "password", authenticationTypes);

        Assert.Throws<PlatformNotSupportedException>(() => entry.BuildOptions());
    }

    [Fact]
    public void Linux_negotiate_with_explicit_credentials_is_decided_by_the_runtime_bind()
    {
        using var entry = new DirectoryEntry(
            TestSettings.PathFor(TestSettings.BaseDn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            AuthenticationTypes.Secure);

        if (OperatingSystem.IsLinux())
        {
            // The Linux S.DS.Protocols implementation currently rejects an
            // explicit credential at Negotiate BindHelper even when GSSAPI's
            // NTLM mechanism is installed. Do not reject it before Bind(): a
            // future/runtime-specific implementation may support it.
            var error = Assert.Throws<System.Runtime.InteropServices.COMException>(
                () => entry.SchemaClassName);
            Assert.Contains("not supported", error.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        Assert.Equal("domainDNS", entry.SchemaClassName);
    }
}
