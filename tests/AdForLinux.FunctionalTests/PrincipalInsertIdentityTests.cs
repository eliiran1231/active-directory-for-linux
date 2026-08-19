using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class PrincipalInsertIdentityTests
{
    private static PrincipalContext Context() =>
        TestSettings.CreatePrincipalContext(TestDirectory.UsersContainer);

    [Fact]
    public void Save_reloads_generated_identity_for_new_principal_types()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var userName = $"adfl-i71-u-{suffix}";
        var groupName = $"adfl-i71-g-{suffix}";
        var computerName = $"adfl-i71-c-{suffix}$";
        var userDn = DnFor(userName);
        var groupDn = DnFor(groupName);
        var computerDn = DnFor(computerName);

        try
        {
            using var context = Context();
            using var user = new UserPrincipal(context)
            {
                Name = userName,
                SamAccountName = userName,
                Enabled = false,
            };
            using var group = new GroupPrincipal(context, groupName);
            using var computer = new ComputerPrincipal(context)
            {
                Name = computerName,
                SamAccountName = computerName,
                Enabled = false,
            };

            user.Save();
            group.Save();
            computer.Save();

            AssertGeneratedIdentity(user, "user");
            AssertGeneratedIdentity(group, "group");
            AssertGeneratedIdentity(computer, "computer");

            // These lookups happen only after the original instances have
            // exposed their generated state, and verify GUID-based equality.
            using var foundUser = UserPrincipal.FindByIdentity(context, userName);
            using var foundGroup = GroupPrincipal.FindByIdentity(context, groupName);
            using var foundComputer = ComputerPrincipal.FindByIdentity(context, computerName);
            Assert.NotNull(foundUser);
            Assert.NotNull(foundGroup);
            Assert.NotNull(foundComputer);
            Assert.Equal(user, foundUser);
            Assert.Equal(group, foundGroup);
            Assert.Equal(computer, foundComputer);

            group.Members.Add(user);
            group.Save();
            using var groups = user.GetGroups(context);
            Assert.Contains(groups, candidate => candidate.Equals(group));
        }
        finally
        {
            TestDirectory.Delete(groupDn);
            TestDirectory.Delete(userDn);
            TestDirectory.Delete(computerDn);
        }
    }

    private static void AssertGeneratedIdentity(Principal principal, string structuralClass)
    {
        Assert.NotNull(principal.Guid);
        Assert.NotNull(principal.SidValue);
        Assert.Equal(structuralClass, principal.StructuralObjectClass, ignoreCase: true);
        Assert.NotEqual(Guid.Empty, Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject()).Guid);
    }

    private static string DnFor(string cn) =>
        $"CN={cn},{TestDirectory.UsersContainer}";
}
