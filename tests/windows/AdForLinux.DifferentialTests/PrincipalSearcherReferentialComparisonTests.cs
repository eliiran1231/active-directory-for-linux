using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class PrincipalSearcherReferentialComparisonTests
{
    [Fact]
    public void Changed_group_members_QBE_exception_matches_in_an_isolated_OU()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var ouName = $"adfl72-{suffix}";
        var userName = $"u-{suffix}";
        var ouDn = $"OU={ouName},{DifferentialSettings.BaseDn}";
        var ouCreated = false;

        try
        {
            using (var domain = Open(DifferentialSettings.BaseDn))
            using (var ou = domain.Children.Add($"OU={ouName}", "organizationalUnit"))
            {
                ou.CommitChanges();
                ouCreated = true;
            }

            using (var ou = Open(ouDn))
            using (var user = ou.Children.Add($"CN={userName}", "user"))
            {
                user.Properties["sAMAccountName"].Value = userName;
                user.CommitChanges();
            }

            using var msContext = MicrosoftContext(ouDn);
            using var ourContext = OurContext(ouDn);
            using var msMember = Ms.UserPrincipal.FindByIdentity(msContext, userName);
            using var ourMember = Ours.UserPrincipal.FindByIdentity(ourContext, userName);
            Assert.NotNull(msMember);
            Assert.NotNull(ourMember);

            using var msFilter = new Ms.GroupPrincipal(msContext)
            {
                GroupScope = Ms.GroupScope.Global,
                IsSecurityGroup = true,
            };
            using var ourFilter = new Ours.GroupPrincipal(ourContext)
            {
                GroupScope = Ours.GroupScope.Global,
                IsSecurityGroup = true,
            };
            _ = msFilter.Members;
            _ = ourFilter.Members;

            using var msSearcher = new Ms.PrincipalSearcher(msFilter);
            using var ourSearcher = new Ours.PrincipalSearcher(ourFilter);
            Assert.Null(Record.Exception(() => msSearcher.GetUnderlyingSearcher()));
            Assert.Null(Record.Exception(() => ourSearcher.GetUnderlyingSearcher()));

            msFilter.Members.Add(msMember!);
            ourFilter.Members.Add(ourMember!);

            CompareInvalidOperation(
                "GetUnderlyingSearcher",
                () => msSearcher.GetUnderlyingSearcher(),
                () => ourSearcher.GetUnderlyingSearcher());
            CompareInvalidOperation(
                "FindOne",
                () => msSearcher.FindOne(),
                () => ourSearcher.FindOne());
            CompareInvalidOperation(
                "FindAll",
                () => msSearcher.FindAll(),
                () => ourSearcher.FindAll());
        }
        finally
        {
            if (ouCreated)
            {
                using var ou = Open(ouDn);
                ou.DeleteTree();
            }
        }
    }

    private static void CompareInvalidOperation(
        string operation,
        Action microsoft,
        Action ours)
    {
        var microsoftException = Record.Exception(microsoft);
        var ourException = Record.Exception(ours);
        Assert.IsType<InvalidOperationException>(microsoftException);
        Assert.IsType<InvalidOperationException>(ourException);
        new Comparison($"changed GroupPrincipal.Members QBE {operation}")
            .Check("exception", microsoftException.GetType().Name, ourException.GetType().Name)
            .Assert();
    }

    private static System.DirectoryServices.DirectoryEntry Open(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ms.PrincipalContext MicrosoftContext(string container) =>
        new(
            Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string container) =>
        new(
            Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
}
