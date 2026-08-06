using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 7: read users through UserPrincipal against smblds.
/// </summary>
public class UserPrincipalReadTests
{
    private static PrincipalContext Context() =>
        new(ContextType.Domain, TestSettings.ServerName, null,
            TestSettings.BindDn, TestSettings.BindPassword);

    private static (string Dn, string Sam, string Upn) SeedUser()
    {
        var sam = $"adfl-user-{Guid.NewGuid():N}".Substring(0, 20);
        var upn = $"{sam}@samdom.example.com";
        var dn = TestDirectory.Create(sam, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = sam,
            ["givenName"] = "Jeff",
            ["sn"] = "Smith",
            ["displayName"] = "Jeff Smith",
            ["mail"] = "jeff.smith@example.com",
            ["userPrincipalName"] = upn,
            ["telephoneNumber"] = "+1-555-0100",
            ["description"] = "seeded by adforlinux tests",
        });

        return (dn, sam, upn);
    }

    [Fact]
    public void FindByIdentity_reads_all_the_common_properties()
    {
        var (dn, sam, _) = SeedUser();
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, sam);

            Assert.NotNull(user);
            Assert.Equal(sam, user!.SamAccountName);
            Assert.Equal(dn, user.DistinguishedName);
            Assert.Equal("Jeff", user.GivenName);
            Assert.Equal("Smith", user.Surname);
            Assert.Equal("Jeff Smith", user.DisplayName);
            Assert.Equal("jeff.smith@example.com", user.EmailAddress);
            Assert.Equal("+1-555-0100", user.VoiceTelephoneNumber);
            Assert.Equal("seeded by adforlinux tests", user.Description);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void FindByIdentity_with_explicit_type_works()
    {
        var (dn, sam, _) = SeedUser();
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, sam);

            Assert.NotNull(user);
            Assert.Equal(sam, user!.SamAccountName);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void FindByIdentity_by_user_principal_name_works()
    {
        var (dn, _, upn) = SeedUser();
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, IdentityType.UserPrincipalName, upn);

            Assert.NotNull(user);
            Assert.Equal(dn, user!.DistinguishedName);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void FindByIdentity_returns_null_when_missing()
    {
        using var context = Context();

        Assert.Null(UserPrincipal.FindByIdentity(context, "no-such-user-xyz-123"));
    }

    [Fact]
    public void GetUnderlyingObject_is_a_directory_entry()
    {
        var (dn, sam, _) = SeedUser();
        try
        {
            using var context = Context();
            var user = UserPrincipal.FindByIdentity(context, sam);

            Assert.NotNull(user);
            Assert.IsType<DirectoryEntry>(user!.GetUnderlyingObject());
            Assert.Equal(typeof(DirectoryEntry), user.GetUnderlyingObjectType());
            Assert.NotNull(user.Guid);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Enabled_reflects_account_state()
    {
        // The built-in Administrator is enabled (userAccountControl 512).
        using var context = Context();
        var admin = UserPrincipal.FindByIdentity(context, "Administrator");

        Assert.NotNull(admin);
        Assert.True(admin!.Enabled);
    }
}
