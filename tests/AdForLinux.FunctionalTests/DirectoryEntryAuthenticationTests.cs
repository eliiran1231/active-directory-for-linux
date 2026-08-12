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
    public void Linux_negotiate_with_explicit_credentials_fails_before_connection_creation()
    {
        var options = new LdapConnectionOptions
        {
            Host = "dc.example.test",
            Port = 389,
            UseSsl = false,
            AuthenticationType = AuthType.Negotiate,
            BindDn = "user@example.test",
            BindPassword = "password",
        };

        var exception = Assert.Throws<PlatformNotSupportedException>(
            () => LdapConnectionFactory.EnsureAuthenticationSupported(options, isWindows: false));

        Assert.Contains("explicit username and password", exception.Message);
    }

    [Fact]
    public void Linux_negotiate_with_default_credentials_remains_supported()
    {
        var options = new LdapConnectionOptions
        {
            Host = "dc.example.test",
            Port = 389,
            UseSsl = false,
            AuthenticationType = AuthType.Negotiate,
        };

        LdapConnectionFactory.EnsureAuthenticationSupported(options, isWindows: false);
    }
}
