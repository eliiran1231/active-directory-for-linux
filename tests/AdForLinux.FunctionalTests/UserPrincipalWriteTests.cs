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
    [DirectoryObjectClass("user")]
    [DirectoryRdnPrefix("CN")]
    private sealed class CustomAuthenticablePrincipal : AuthenticablePrincipal
    {
        public CustomAuthenticablePrincipal(
            PrincipalContext context,
            string samAccountName,
            string password,
            bool enabled)
            : base(context, samAccountName, password, enabled)
        {
        }
    }

    private static PrincipalContext Context() =>
        TestSettings.CreatePrincipalContext(TestDirectory.UsersContainer);

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
    public void Custom_authenticable_principal_can_attempt_a_password_change()
    {
        var name = NewName();
        var dn = DnFor(name);

        try
        {
            using var context = Context();
            using var principal = new CustomAuthenticablePrincipal(
                context, name, "Str0ng!Passw0rd#2026", enabled: true);
            principal.Save();

            Assert.Throws<PasswordException>(() => principal.ChangePassword(
                "Wr0ng!OldPass#2026", "Str0ng!NewPass#2026"));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void FindByExpirationTime_returns_the_matching_saved_user()
    {
        var name = NewName();
        var dn = DnFor(name);
        var expiration = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);

        try
        {
            using var context = Context();
            using (var user = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
                AccountExpirationDate = expiration,
            })
            {
                user.Save();
            }

            using var found = UserPrincipal.FindByExpirationTime(
                context, expiration,
                AdForLinux.DirectoryServices.AccountManagement.MatchType.Equals);
            Assert.Contains(found, principal => principal.SamAccountName == name);
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
    public void Rejected_deferred_password_rolls_back_and_corrected_user_can_be_saved()
    {
        var name = NewName();
        var dn = DnFor(name);

        try
        {
            using var context = Context();
            using var user = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
                DisplayName = "Rollback retry",
                Enabled = false,
            };
            user.SetPassword("short");

            Assert.Throws<InvalidOperationException>(user.Save);
            Assert.False(user.IsPersisted);
            Assert.Null(user.DistinguishedName);
            Assert.Null(user.Guid);
            Assert.Equal(name, user.Name);
            Assert.Equal(name, user.SamAccountName);
            Assert.Equal("Rollback retry", user.DisplayName);
            Assert.Throws<InvalidOperationException>(user.GetUnderlyingObject);
            Assert.Null(UserPrincipal.FindByIdentity(context, name));

            using var corrected = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
                DisplayName = "Rollback retry",
                Enabled = false,
            };
            corrected.SetPassword("Str0ng!Passw0rd#2026");
            corrected.Save();

            Assert.True(corrected.IsPersisted);
            Assert.Equal(dn, corrected.DistinguishedName);
            using var found = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(found);
            Assert.Equal("Rollback retry", found!.DisplayName);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Rollback_cleanup_failure_does_not_replace_the_save_failure()
    {
        var saveFailure = new InvalidOperationException("save failed");
        var cleanupFailure = new InvalidOperationException("cleanup failed");

        var observed = Assert.Throws<InvalidOperationException>((Action)(() =>
        {
            try
            {
                throw saveFailure;
            }
            catch
            {
                Assert.False(Principal.TryRollbackCreatedEntry(() => throw cleanupFailure));
                throw;
            }
        }));

        Assert.Same(saveFailure, observed);
    }

    [Fact]
    public void Failed_post_create_cleanup_retains_the_moved_orphan()
    {
        var name = NewName();
        var originalDn = DnFor(name);
        var orphanDn = $"CN={name},{TestDirectory.ComputersContainer}";
        var saveFailure = new InvalidOperationException("post-create work failed");

        try
        {
            using var context = Context();
            using var user = new MoveThenFailUserPrincipal(
                context, TestDirectory.ComputersContainer, saveFailure)
            {
                Name = name,
                SamAccountName = name,
            };

            var observed = Assert.Throws<InvalidOperationException>(user.Save);

            Assert.Same(saveFailure, observed);
            Assert.True(user.IsPersisted);
            Assert.Same(user.AttachedEntry, user.GetUnderlyingObject());
            Assert.Equal(orphanDn, user.DistinguishedName);
            Assert.Equal(name, user.Name);
            Assert.NotNull(user.Guid);
            Assert.Null(UserPrincipal.FindByIdentity(context, name));

            using (var orphanContext = TestSettings.CreatePrincipalContext(
                       TestDirectory.ComputersContainer))
            using (var orphan = UserPrincipal.FindByIdentity(orphanContext, name))
            {
                Assert.NotNull(orphan);
                Assert.Equal(orphanDn, orphan!.DistinguishedName);
            }

            // The retained entry is still usable, so the caller can explicitly
            // remove the orphan after inspecting the failed save state.
            user.Delete();
            Assert.False(user.IsPersisted);

            using var check = TestSettings.CreatePrincipalContext(TestDirectory.ComputersContainer);
            Assert.Null(UserPrincipal.FindByIdentity(check, name));
        }
        finally
        {
            TestDirectory.Delete(originalDn);
            TestDirectory.Delete(orphanDn);
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

    [DirectoryObjectClass("user")]
    [DirectoryRdnPrefix("CN")]
    private sealed class MoveThenFailUserPrincipal : UserPrincipal
    {
        private readonly string _destinationDn;
        private readonly InvalidOperationException _saveFailure;

        public MoveThenFailUserPrincipal(
            PrincipalContext context,
            string destinationDn,
            InvalidOperationException saveFailure)
            : base(context)
        {
            _destinationDn = destinationDn;
            _saveFailure = saveFailure;
        }

        internal DirectoryEntry? AttachedEntry => Entry;

        private protected override void OnAfterSave()
        {
            base.OnAfterSave();
            if (!IsInserting)
            {
                return;
            }

            // Moving the completed add makes SaveCore's best-effort delete
            // against the original parent fail with no-such-object, while the
            // same live DirectoryEntry remains available at its new DN.
            using var destination = new DirectoryEntry(
                TestSettings.PathFor(_destinationDn),
                TestSettings.BindDn,
                TestSettings.BindPassword,
                TestSettings.UseTls
                    ? AuthenticationTypes.SecureSocketsLayer
                    : AuthenticationTypes.None);
            Entry!.MoveTo(destination);
            throw _saveFailure;
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
                Assert.Throws<InvalidOperationException>(() => user.DistinguishedName);
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
    public void Required_name_setters_validate_persisted_and_deleted_principals()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
            ["description"] = "clear me",
        });

        try
        {
            using var context = Context();
            using var user = UserPrincipal.FindByIdentity(context, name);
            Assert.NotNull(user);

            foreach (var value in new string?[] { null, string.Empty })
            {
                var nameException = Assert.Throws<ArgumentNullException>(() => user!.Name = value);
                var samException = Assert.Throws<ArgumentNullException>(
                    () => user!.SamAccountName = value);
                Assert.Equal("value", nameException.ParamName);
                Assert.Equal("value", samException.ParamName);
            }

            user!.Description = null;
            user.Save();
            Assert.Null(user.Description);

            user.Delete();
            foreach (var value in new string?[] { null, string.Empty })
            {
                Assert.Equal("value", Assert.Throws<ArgumentNullException>(
                    () => user.Name = value).ParamName);
                Assert.Equal("value", Assert.Throws<ArgumentNullException>(
                    () => user.SamAccountName = value).ParamName);
            }

            Assert.Throws<InvalidOperationException>(() => user.Name = "valid");
            Assert.Throws<InvalidOperationException>(() => user.SamAccountName = "valid");
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
            Assert.Equal(0L, entry.Properties["pwdLastSet"].Value);
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
            Assert.Equal(0L, entry.Properties["lockoutTime"].Value);
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
    public void SetPassword_before_save_is_applied_when_the_user_is_saved()
    {
        var name = NewName();
        var dn = DnFor(name);
        using var context = Context();
        try
        {
            using var user = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
                UserPrincipalName = $"{name}@samdom.example.com",
                Enabled = true,
            };
            user.SetPassword("Str0ng!Passw0rd#2026");
            user.Save();

            Assert.True(context.ValidateCredentials(
                $"{name}@samdom.example.com", "Str0ng!Passw0rd#2026"));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void ChangePassword_accepts_the_new_password_after_expiration()
    {
        var name = NewName();
        var dn = DnFor(name);
        var oldPassword = "Str0ng!OldPass#2026";
        var newPassword = "Str0ng!NewPass#2026";
        try
        {
            using var context = Context();
            using (var user = new UserPrincipal(context, name, oldPassword, enabled: true))
            {
                user.UserPrincipalName = $"{name}@samdom.example.com";
                user.Save();
                user.ExpirePasswordNow();
                user.ChangePassword(oldPassword, newPassword);
            }

            Assert.True(context.ValidateCredentials($"{name}@samdom.example.com", newPassword));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void ChangePassword_wrong_old_password_throws_PasswordException()
    {
        var name = NewName();
        var dn = DnFor(name);
        try
        {
            using var context = Context();
            using var user = new UserPrincipal(
                context, name, "Str0ng!OldPass#2026", enabled: true);
            user.UserPrincipalName = $"{name}@samdom.example.com";
            user.Save();
            user.ExpirePasswordNow();

            var exception = Assert.Throws<PasswordException>(
                () => user.ChangePassword("Wr0ng!OldPass#2026", "Str0ng!NewPass#2026"));
            Assert.IsType<DirectoryServicesCOMException>(
                exception.InnerException);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void ChangePassword_policy_rejection_throws_PasswordException()
    {
        var name = NewName();
        var dn = DnFor(name);
        try
        {
            using var context = Context();
            using var user = new UserPrincipal(
                context, name, "Str0ng!OldPass#2026", enabled: true);
            user.UserPrincipalName = $"{name}@samdom.example.com";
            user.Save();
            user.ExpirePasswordNow();

            Assert.Throws<PasswordException>(
                () => user.ChangePassword("Str0ng!OldPass#2026", "short"));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void SetPassword_policy_rejection_throws_InvalidOperationException()
    {
        var name = NewName();
        var dn = DnFor(name);
        try
        {
            using var context = Context();
            using var user = new UserPrincipal(
                context, name, "Str0ng!OldPass#2026", enabled: true);
            user.Save();

            Assert.Throws<InvalidOperationException>(() => user.SetPassword("short"));
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Save_with_a_rejected_deferred_password_throws_InvalidOperationException()
    {
        var name = NewName();
        var dn = DnFor(name);
        try
        {
            using var context = Context();
            using var user = new UserPrincipal(context)
            {
                Name = name,
                SamAccountName = name,
                Enabled = false,
            };
            user.SetPassword("short");

            var exception = Assert.Throws<InvalidOperationException>(user.Save);
            Assert.IsType<DirectoryServicesCOMException>(
                exception.InnerException);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void UserCannotChangePassword_round_trips_through_the_change_password_acl()
    {
        var name = NewName();
        var dn = TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });
        try
        {
            using var context = Context();
            using (var user = UserPrincipal.FindByIdentity(context, name)!)
            {
                user.UserCannotChangePassword = true;
                user.Save();
            }

            using (var denied = UserPrincipal.FindByIdentity(context, name)!)
            {
                Assert.True(denied.UserCannotChangePassword);
                denied.UserCannotChangePassword = false;
                denied.Save();
            }

            using var allowed = UserPrincipal.FindByIdentity(context, name)!;
            Assert.False(allowed.UserCannotChangePassword);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }
}
