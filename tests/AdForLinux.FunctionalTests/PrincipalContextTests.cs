using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 6: PrincipalContext against smblds.
/// </summary>
public class PrincipalContextTests
{
    private static PrincipalContext Authenticated(string? container = null) =>
        new(ContextType.Domain, TestSettings.ServerName, container,
            TestSettings.BindDn, TestSettings.BindPassword);

    [Fact]
    public void Container_defaults_to_the_default_naming_context()
    {
        using var context = Authenticated();

        Assert.Equal(TestSettings.BaseDn, context.Container, ignoreCase: true);
    }

    [Fact]
    public void Container_uses_the_value_given()
    {
        var users = $"CN=Users,{TestSettings.BaseDn}";
        using var context = Authenticated(users);

        Assert.Equal(users, context.Container);
    }

    [Fact]
    public void ConnectedServer_is_the_host()
    {
        using var context = Authenticated();

        Assert.Equal(TestSettings.Host, context.ConnectedServer);
        Assert.Equal(TestSettings.Port, context.Port);
        Assert.True(context.UseSsl);
    }

    [Fact]
    public void ValidateCredentials_is_true_for_correct_password()
    {
        using var context = Authenticated();

        Assert.True(context.ValidateCredentials(TestSettings.BindDn, TestSettings.BindPassword));
    }

    [Fact]
    public void ValidateCredentials_is_false_for_wrong_password()
    {
        using var context = Authenticated();

        Assert.False(context.ValidateCredentials(TestSettings.BindDn, "definitely-wrong-password"));
    }

    [Fact]
    public void Issue_11_constructor_overloads_and_options_are_available()
    {
        using var credentialContext = new PrincipalContext(
            ContextType.Domain,
            "dc.example.test",
            "bind-user",
            "bind-password");
        Assert.Equal("bind-user", credentialContext.UserName);
        Assert.Equal(
            ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer,
            credentialContext.Options);

        using var optionsContext = new PrincipalContext(
            ContextType.Domain,
            "dc.example.test",
            "DC=example,DC=test",
            ContextOptions.SimpleBind);
        Assert.Equal(ContextOptions.SimpleBind, optionsContext.Options);
        Assert.False(optionsContext.UseSsl);
        Assert.Equal(389, optionsContext.Port);
    }

    [Fact]
    public void ValidateCredentials_honors_explicit_context_options()
    {
        using var context = Authenticated();

        Assert.True(context.ValidateCredentials(
            TestSettings.BindDn,
            TestSettings.BindPassword,
            ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer));
        Assert.False(context.ValidateCredentials(
            TestSettings.BindDn,
            "definitely-wrong-password",
            ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer));
    }

    [Fact]
    public void Serverless_context_is_not_supported_on_linux()
    {
        Assert.Throws<NotSupportedException>(() => new PrincipalContext(ContextType.Domain));
    }

    [Fact]
    public void Machine_context_is_not_supported()
    {
        Assert.Throws<NotSupportedException>(
            () => new PrincipalContext(ContextType.Machine, TestSettings.ServerName));
    }
}
