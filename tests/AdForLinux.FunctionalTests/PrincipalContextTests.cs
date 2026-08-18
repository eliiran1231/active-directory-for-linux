using AdForLinux.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 6: PrincipalContext against smblds.
/// </summary>
public class PrincipalContextTests
{
    private static PrincipalContext Authenticated(string? container = null) =>
        TestSettings.CreatePrincipalContext(container);

    [Fact]
    public void Container_is_null_when_no_container_was_supplied()
    {
        using var context = Authenticated();

        Assert.Null(context.Container);
    }

    [Fact]
    public void Well_known_container_values_preserve_renamed_or_moved_distinguished_names()
    {
        var users = $"OU=Renamed Users,OU=Provisioning,{TestSettings.BaseDn}";
        var computers = $"OU=Workstations,OU=Provisioning,{TestSettings.BaseDn}";
        object?[] values =
        {
            $"B:32:A9D1CA15768811D1ADED00C04FD8D5CD:{users}",
            System.Text.Encoding.UTF8.GetBytes(
                $"B:32:AA312825768811D1ADED00C04FD8D5CD:{computers}"),
        };

        Assert.True(PrincipalContext.TryResolveWellKnownContainers(
            values, out var resolvedUsers, out var resolvedComputers));
        Assert.Equal(users, resolvedUsers);
        Assert.Equal(computers, resolvedComputers);
    }

    [Fact]
    public void Default_context_creates_principals_in_well_known_containers()
    {
        using var context = Authenticated();
        var suffix = Guid.NewGuid().ToString("N")[..8];
        using var user = new UserPrincipal(context) { Name = $"i38-u-{suffix}" };
        using var group = new GroupPrincipal(context) { Name = $"i38-g-{suffix}" };
        using var computer = new ComputerPrincipal(context) { Name = $"i38-c-{suffix}" };

        try
        {
            user.Save();
            group.Save();
            computer.Save();

            Assert.Equal(TestDirectory.UsersContainer,
                ParentOf(user.DistinguishedName!), ignoreCase: true);
            Assert.Equal(TestDirectory.UsersContainer,
                ParentOf(group.DistinguishedName!), ignoreCase: true);
            Assert.Equal($"CN=Computers,{TestSettings.BaseDn}",
                ParentOf(computer.DistinguishedName!), ignoreCase: true);
        }
        finally
        {
            if (user.DistinguishedName is { } userDn) TestDirectory.Delete(userDn);
            if (group.DistinguishedName is { } groupDn) TestDirectory.Delete(groupDn);
            if (computer.DistinguishedName is { } computerDn) TestDirectory.Delete(computerDn);
        }
    }

    private static string ParentOf(string distinguishedName) =>
        distinguishedName.Substring(distinguishedName.IndexOf(',') + 1);

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

        Assert.False(context.ValidateCredentials(
            TestSettings.BindDn,
            "definitely-wrong-password",
            ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer));
    }

    [Fact]
    public void ValidateCredentials_without_options_returns_false_for_wrong_password_on_Linux()
    {
        Assert.True(OperatingSystem.IsLinux());
        using var context = Authenticated();

        // Explicit Negotiate remains unavailable in this Linux fixture. The
        // optionless overload must not reach it after LDAPS rejects a bad password.
        Assert.Throws<PrincipalServerDownException>(() => context.ValidateCredentials(
            TestSettings.BindDn,
            "definitely-wrong-password",
            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing));

        Assert.False(context.ValidateCredentials(
            TestSettings.BindDn,
            "definitely-wrong-password"));
    }

    [Fact]
    public void ValidateCredentials_returns_false_when_fallback_rejects_wrong_password_on_Linux()
    {
        Assert.True(OperatingSystem.IsLinux());
        using var context = Authenticated();
        var lastMethod = typeof(PrincipalContext).GetField(
            "_lastCredentialValidationMethod",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(lastMethod);
        lastMethod.SetValue(context, Enum.Parse(lastMethod.FieldType, "Negotiate"));

        // Negotiate fails in this fixture, forcing the second Simple+SSL bind.
        Assert.False(context.ValidateCredentials(
            TestSettings.BindDn,
            "definitely-wrong-password"));
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
            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing,
            credentialContext.Options);
        Assert.False(credentialContext.UseSsl);
        Assert.Equal(389, credentialContext.Port);

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
    public void Explicit_context_options_map_to_ldap_authentication_and_protection()
    {
        using var simpleContext = new PrincipalContext(
            ContextType.Domain,
            "dc.example.test",
            "DC=example,DC=test",
            ContextOptions.SimpleBind,
            "user@example.test",
            "password");
        var simple = simpleContext.BuildOptions();
        Assert.Equal(AuthType.Basic, simple.AuthenticationType);
        Assert.False(simple.Signing);
        Assert.False(simple.Sealing);

        using var negotiateContext = new PrincipalContext(
            ContextType.Domain,
            "dc.example.test",
            "DC=example,DC=test",
            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing,
            "user@example.test",
            "password");
        var negotiate = negotiateContext.BuildOptions();
        Assert.Equal(AuthType.Negotiate, negotiate.AuthenticationType);
        Assert.True(negotiate.Signing);
        Assert.True(negotiate.Sealing);
    }

    [Fact]
    public void ValidateCredentials_rejects_mismatched_null_credentials()
    {
        using var context = new PrincipalContext(
            ContextType.Domain, "dc.example.test", "DC=example,DC=test");

        Assert.Throws<ArgumentException>(() => context.ValidateCredentials(
            null!, "password", ContextOptions.SimpleBind));
        Assert.Throws<ArgumentException>(() => context.ValidateCredentials(
            "user", null!, ContextOptions.SimpleBind));
    }

    [Theory]
    [InlineData(0)]
    [InlineData((int)(ContextOptions.Negotiate | ContextOptions.SimpleBind))]
    public void ValidateCredentials_does_not_apply_constructor_option_validation(int rawOptions)
    {
        using var context = new PrincipalContext(
            ContextType.Domain, "127.0.0.1:1", "DC=example,DC=test");

        var exception = Record.Exception(() => context.ValidateCredentials(
            "user", "password", (ContextOptions)rawOptions));
        Assert.False(exception is ArgumentException);
        Assert.False(exception is System.ComponentModel.InvalidEnumArgumentException);
    }

    [Fact]
    public void ValidateCredentials_without_options_is_independent_of_context_options()
    {
        using var context = new PrincipalContext(
            ContextType.Domain,
            TestSettings.ServerName,
            TestDirectory.UsersContainer,
            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing,
            TestSettings.BindDn,
            TestSettings.BindPassword);

        Assert.Equal(
            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing,
            context.Options);
        Assert.True(context.ValidateCredentials(
            TestSettings.BindDn, TestSettings.BindPassword));
    }

    [Fact]
    public void ValidateCredentials_translates_server_unavailable()
    {
        using var context = new PrincipalContext(
            ContextType.Domain, "127.0.0.2", "DC=example,DC=test");

        Assert.Throws<PrincipalServerDownException>(() => context.ValidateCredentials(
            "user", "password", ContextOptions.SimpleBind));
    }

    [Fact]
    public void Disposed_context_rejects_properties_and_operations_with_microsoft_object_name()
    {
        var context = new PrincipalContext(
            ContextType.Domain, "dc.example.test", "DC=example,DC=test");

        context.Dispose();
        context.Dispose();

        Action[] members =
        {
            () => _ = context.ContextType,
            () => _ = context.Name,
            () => _ = context.Container,
            () => _ = context.UserName,
            () => _ = context.Options,
            () => _ = context.ConnectedServer,
            () => _ = context.Port,
            () => _ = context.UseSsl,
            () => context.ValidateCredentials("user", "password"),
            () => context.ValidateCredentials("user", "password", ContextOptions.SimpleBind),
        };

        foreach (var member in members)
        {
            var exception = Assert.Throws<ObjectDisposedException>(member);
            Assert.Equal("PrincipalContext", exception.ObjectName);
        }
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
