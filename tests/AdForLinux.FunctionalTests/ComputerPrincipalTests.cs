using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using AccountMatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public class ComputerPrincipalTests
{
    private static PrincipalContext Context() =>
        new(ContextType.Domain, TestSettings.ServerName, TestDirectory.UsersContainer,
            TestSettings.BindDn, TestSettings.BindPassword);

    [Fact]
    public void Constructor_and_save_create_a_computer_account()
    {
        var name = $"adfl-nc-{Guid.NewGuid():N}"[..18];
        var accountName = $"{name}$";
        var dn = $"CN={accountName},{TestDirectory.UsersContainer}";

        try
        {
            using var context = Context();
            using (var computer = new ComputerPrincipal(
                context, accountName, "Str0ng!ComputerPass#2026", enabled: false))
            {
                computer.ServicePrincipalNames.Add($"HOST/{name}.samdom.example.com");
                computer.Save();
                Assert.Equal(dn, computer.DistinguishedName);
            }

            using var found = ComputerPrincipal.FindByIdentity(context, accountName);
            Assert.NotNull(found);
            Assert.False(found!.Enabled);
            Assert.Single(found.ServicePrincipalNames);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Constructor_can_create_an_enabled_computer_with_a_valid_password()
    {
        var name = $"adfl-ec-{Guid.NewGuid():N}"[..18];
        var accountName = $"{name}$";
        var dn = $"CN={accountName},{TestDirectory.UsersContainer}";

        try
        {
            using var context = Context();
            using (var computer = new ComputerPrincipal(
                context, accountName, "Str0ng!ComputerPass#2026", enabled: true))
            {
                computer.Save();
            }

            using var found = ComputerPrincipal.FindByIdentity(context, accountName);
            Assert.NotNull(found);
            Assert.True(found!.Enabled);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }

    [Fact]
    public void Computer_can_be_found_materialized_and_updated()
    {
        var name = $"adfl-c-{Guid.NewGuid():N}"[..18];
        var accountName = $"{name}$";
        var firstSpn = $"HOST/{name}.samdom.example.com";
        var secondSpn = $"RestrictedKrbHost/{name}.samdom.example.com";
        var dn = TestDirectory.Create(name, "computer", new Dictionary<string, string>
        {
            ["sAMAccountName"] = accountName,
            ["servicePrincipalName"] = firstSpn,
        });

        try
        {
            using var context = Context();
            using (var computer = ComputerPrincipal.FindByIdentity(context, accountName))
            {
                Assert.NotNull(computer);
                Assert.Contains(firstSpn, computer!.ServicePrincipalNames);
                computer.ServicePrincipalNames.Add(secondSpn);
                computer.Save();
            }

            using (var query = new ComputerPrincipal(context) { SamAccountName = accountName })
            using (var searcher = new PrincipalSearcher(query))
            using (var found = searcher.FindOne())
            {
                Assert.IsType<ComputerPrincipal>(found);
            }

            using var advancedQuery = new ComputerPrincipal(context);
            advancedQuery.AdvancedSearchFilter.BadLogonCount(0, AccountMatchType.GreaterThanOrEquals);
            using var advancedSearcher = new PrincipalSearcher(advancedQuery);
            using var advancedFound = advancedSearcher.FindOne();
            Assert.IsType<ComputerPrincipal>(advancedFound);

            using var reloaded = ComputerPrincipal.FindByIdentity(context, accountName);
            Assert.Contains(secondSpn, reloaded!.ServicePrincipalNames);
        }
        finally
        {
            TestDirectory.Delete(dn);
        }
    }
}
