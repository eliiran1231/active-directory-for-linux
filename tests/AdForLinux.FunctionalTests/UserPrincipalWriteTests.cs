using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 8: create, change, and delete users through UserPrincipal against
/// smblds. Each test cleans up what it makes.
/// </summary>
public class UserPrincipalWriteTests
{
    private static PrincipalContext Context() =>
        new(ContextType.Domain, TestSettings.ServerName, TestDirectory.UsersContainer,
            TestSettings.BindDn, TestSettings.BindPassword);

    private static string NewName() => $"adfl-w-{Guid.NewGuid():N}".Substring(0, 18);

    private static string DnFor(string cn) => $"CN={cn},{TestDirectory.UsersContainer}";

    [Fact]
    public void Four_argument_constructor_can_create_an_enabled_user_with_a_valid_password()
    {
        var name = NewName();
        var dn = DnFor(name);

        try
        {
            using var context = Context();
            using (var user = new UserPrincipal(
                context, name, "Str0ng!Passw0rd#2026", enabled: true))
            {
                user.UserPrincipalName = $"{name}@samdom.example.com";
                user.Save();
            }

            using var found = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(found);
            Assert.True(found!.Enabled);
            Assert.True(context.ValidateCredentials(
                $"{name}@samdom.example.com", "Str0ng!Passw0rd#2026"));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Save_creates_a_new_user()
    {
        var name = NewName();
        try
        {
            using (var context = Context())
            {
                using var user = new UserPrincipal(context)
                {
                    Name = name,
                    SamAccountName = name,
                    GivenName = "Ada",
                    Surname = "Lovelace",
                    DisplayName = "Ada Lovelace",
                    EmailAddress = "ada@example.com",
                };
                user.Save();

                Assert.Equal(DnFor(name), user.DistinguishedName);
            }

            // Read it back with a fresh context.
            using var check = Context();
            var found = UserPrincipal.FindByIdentity(check, name);
            Assert.NotNull(found);
            Assert.Equal("Ada", found!.GivenName);
            Assert.Equal("Lovelace", found.Surname);
            Assert.Equal("ada@example.com", found.EmailAddress);
        }
        finally
        {
            TestDirectory.Delete(DnFor(name));
        }
    }

    [Fact]
    public void Save_updates_an_existing_user()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
            ["displayName"] = "before",
        });

        try
        {
            using (var context = Context())
            {
                var user = UserPrincipal.FindByIdentity(context, name);
                Assert.NotNull(user);
                user!.DisplayName = "after";
                user.VoiceTelephoneNumber = "+1-555-0199";
                user.Save();
                user.Dispose();
            }

            using var check = Context();
            var found = UserPrincipal.FindByIdentity(check, name);
            Assert.Equal("after", found!.DisplayName);
            Assert.Equal("+1-555-0199", found.VoiceTelephoneNumber);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Delete_removes_the_user()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using (var context = Context())
            {
                var user = UserPrincipal.FindByIdentity(context, name);
                Assert.NotNull(user);
                user!.Delete();
                Assert.Null(user.DistinguishedName);
            }

            using var check = Context();
            Assert.Null(UserPrincipal.FindByIdentity(check, name));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void SetPassword_then_the_password_works_for_binding()
    {
        var name = NewName();
        var password = "Str0ng!Passw0rd#2026";
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
            ["userPrincipalName"] = $"{name}@samdom.example.com",
        });

        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);

            user!.SetPassword(password);

            // Enable the account so the new password can actually be used.
            user.Enabled = true;
            user.Save();
            user.Dispose();

            Assert.True(context.ValidateCredentials($"{name}@samdom.example.com", password));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Enabled_can_be_turned_on_and_off()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);

            // A freshly created user with no password is disabled.
            user!.SetPassword("Str0ng!Passw0rd#2026");
            user.Enabled = true;
            user.Save();
            user.Dispose();

            var enabled = UserPrincipal.FindByIdentity(context, name);
            Assert.True(enabled!.Enabled);

            enabled.Enabled = false;
            enabled.Save();
            enabled.Dispose();

            var disabled = UserPrincipal.FindByIdentity(context, name);
            Assert.False(disabled!.Enabled);
            disabled.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void ExpirePasswordNow_sets_pwd_last_set_to_zero()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);

            user!.ExpirePasswordNow();
            user.Dispose();

            using var entry = new DirectoryEntry(
                TestSettings.PathFor(dn), TestSettings.BindDn, TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            Assert.Equal("0", entry.Properties["pwdLastSet"].Value);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void UnlockAccount_clears_lockout_time()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);

            user!.UnlockAccount();
            user.Dispose();

            using var entry = new DirectoryEntry(
                TestSettings.PathFor(dn), TestSettings.BindDn, TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            Assert.Equal("0", entry.Properties["lockoutTime"].Value);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void SmartcardLogonRequired_round_trips()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);
            Assert.False(user!.SmartcardLogonRequired);

            user.SmartcardLogonRequired = true;
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name);
            Assert.True(found!.SmartcardLogonRequired);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void SetPassword_before_save_throws()
    {
        using var context = Context();
        using var user = new UserPrincipal(context) { Name = NewName() };

        Assert.Throws<InvalidOperationException>(() => user.SetPassword("Str0ng!Passw0rd#2026"));
    }
}
