using Our = AdForLinux.DirectoryServices.AccountManagement;
using MsAccount = System.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.DifferentialTests;

public class DefaultContainerComparisonTests
{
    [Fact]
    public void Context_without_explicit_container_matches_Microsoft_and_queries_domain_root()
    {
        using var microsoft = new MsAccount.PrincipalContext(
            MsAccount.ContextType.Domain,
            DifferentialSettings.ServerName,
            null,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var ours = new Our.PrincipalContext(
            Our.ContextType.Domain,
            DifferentialSettings.ServerName,
            null,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

        Assert.Null(microsoft.Container);
        Assert.Null(ours.Container);

        // The object lives in this worker's isolated OU, not a default Users container.
        // A context with no container must still query from the domain root.
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var name = $"i38-q-{suffix}";
        var dn = $"CN={name},{DifferentialSettings.BaseDn}";
        try
        {
            using (var parent = new System.DirectoryServices.DirectoryEntry(
                DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes))
            using (var user = parent.Children.Add($"CN={name}", "user"))
            {
                user.Properties["sAMAccountName"].Value = name;
                user.CommitChanges();
            }

            using var microsoftUser = MsAccount.UserPrincipal.FindByIdentity(microsoft, name);
            using var ourUser = Our.UserPrincipal.FindByIdentity(ours, name);
            Assert.NotNull(microsoftUser);
            Assert.NotNull(ourUser);
            Assert.Equal(microsoftUser.DistinguishedName, ourUser.DistinguishedName, ignoreCase: true);
        }
        finally
        {
            try
            {
                using var entry = new System.DirectoryServices.DirectoryEntry(
                    DifferentialSettings.PathFor(dn),
                    DifferentialSettings.BindDn,
                    DifferentialSettings.BindPassword,
                    DifferentialSettings.MicrosoftAuthenticationTypes);
                entry.DeleteTree();
            }
            catch
            {
                // Best-effort cleanup if creation failed before the entry existed.
            }
        }
    }
}
