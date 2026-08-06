using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 11: the extra account properties — dates, counters, and UAC flags.
/// </summary>
public class AccountPropertyTests
{
    private static PrincipalContext Context() =>
        new(ContextType.Domain, TestSettings.ServerName, TestDirectory.UsersContainer,
            TestSettings.BindDn, TestSettings.BindPassword);

    private static string NewName() => $"adfl-p-{Guid.NewGuid():N}".Substring(0, 18);

    private static string SeedUser(string name) =>
        TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

    [Fact]
    public void A_new_account_never_expires_and_never_logged_on()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;

            // accountExpires is 0 on a fresh object, which means "never".
            Assert.Null(user.AccountExpirationDate);
            Assert.Null(user.LastLogon);
            Assert.Null(user.AccountLockoutTime);
            Assert.False(user.IsAccountLockedOut());
            Assert.Equal(0, user.BadLogonCount);
            user.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void AccountExpirationDate_round_trips_in_utc()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;

            // Whole seconds, so the FILETIME conversion is exact.
            var expires = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
            user.AccountExpirationDate = expires;
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.Equal(expires, found.AccountExpirationDate);
            Assert.Equal(DateTimeKind.Utc, found.AccountExpirationDate!.Value.Kind);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void AccountExpirationDate_can_be_cleared_back_to_never()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;
            user.AccountExpirationDate = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
            user.Save();
            user.AccountExpirationDate = null;
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.Null(found.AccountExpirationDate);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void PasswordNeverExpires_round_trips()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;
            Assert.False(user.PasswordNeverExpires);

            user.PasswordNeverExpires = true;
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.True(found.PasswordNeverExpires);

            found.PasswordNeverExpires = false;
            found.Save();
            found.Dispose();

            var cleared = UserPrincipal.FindByIdentity(context, name)!;
            Assert.False(cleared.PasswordNeverExpires);
            cleared.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void DelegationPermitted_is_stored_inverted()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;

            // No NOT_DELEGATED bit by default, so delegation is permitted.
            Assert.True(user.DelegationPermitted);

            user.DelegationPermitted = false;
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.False(found.DelegationPermitted);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void ExpirePasswordNow_makes_last_password_set_null()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;
            user.ExpirePasswordNow();
            user.Dispose();

            // pwdLastSet 0 means "must change at next logon", which reads as null.
            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.Null(found.LastPasswordSet);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void SetPassword_sets_last_password_set()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;
            user.SetPassword("Str0ng!Passw0rd#2026");
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.NotNull(found.LastPasswordSet);
            Assert.Equal(DateTimeKind.Utc, found.LastPasswordSet!.Value.Kind);
            // Should be right about now.
            Assert.True((DateTime.UtcNow - found.LastPasswordSet.Value).Duration() < TimeSpan.FromMinutes(10));
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Text_neighbour_properties_round_trip()
    {
        var name = NewName();
        var dn = SeedUser(name);
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, name)!;
            user.MiddleName = "Quentin";
            user.EmployeeId = "E-4242";
            user.HomeDirectory = @"\\server\home\jeff";
            user.HomeDrive = "H:";
            user.ScriptPath = "logon.bat";
            user.Save();
            user.Dispose();

            var found = UserPrincipal.FindByIdentity(context, name)!;
            Assert.Equal("Quentin", found.MiddleName);
            Assert.Equal("E-4242", found.EmployeeId);
            Assert.Equal(@"\\server\home\jeff", found.HomeDirectory);
            Assert.Equal("H:", found.HomeDrive);
            Assert.Equal("logon.bat", found.ScriptPath);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }
}
