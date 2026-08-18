using Xunit;
using Ms = System.DirectoryServices;
using MsAm = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices;
using OurAm = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class ExceptionTranslationComparisonTests
{
    [Fact]
    public void MissingObjectHasDirectoryServicesComExceptionParity()
    {
        var dn = $"CN=issue41-missing-{Guid.NewGuid():N},{DifferentialSettings.BaseDn}";

        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

        var microsoftException = Record.Exception(microsoft.RefreshCache);
        var ourException = Record.Exception(ours.RefreshCache);

        AssertEquivalent("missing object", microsoftException, ourException);
        Assert.Equal(unchecked((int)0x80072030), ourException!.HResult);
    }

    [Fact]
    public void DuplicateCreateHasLowAndHighLevelParity()
    {
        var lowName = $"i41l-{Guid.NewGuid():N}"[..19];
        CompareDuplicateDirectoryEntry(lowName);

        var highName = $"i41h-{Guid.NewGuid():N}"[..19];
        CompareDuplicatePrincipal(highName);
    }

    [Fact]
    public void InvalidFilterHasDirectoryServicesComExceptionParity()
    {
        using var microsoftRoot = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourRoot = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var microsoft = new Ms.DirectorySearcher(microsoftRoot, "(|invalid)");
        using var ours = new Ours.DirectorySearcher(ourRoot, "(|invalid)");

        AssertEquivalent(
            "invalid filter",
            Record.Exception(microsoft.FindOne),
            Record.Exception(ours.FindOne));
    }

    [Fact]
    public void ServerUnavailableHasLowAndHighLevelParity()
    {
        AssertEquivalent(
            "server unavailable DirectoryEntry",
            Record.Exception(() =>
            {
                using var entry = new Ms.DirectoryEntry("LDAP://127.0.0.1:1/DC=unavailable");
                entry.RefreshCache();
            }),
            Record.Exception(() =>
            {
                using var entry = new Ours.DirectoryEntry("LDAP://127.0.0.1:1/DC=unavailable");
                entry.RefreshCache();
            }));

        AssertEquivalent(
            "server unavailable PrincipalContext",
            Record.Exception(() => FindAgainstUnavailableMicrosoftServer()),
            Record.Exception(() => FindAgainstUnavailableOurServer()));
    }

    private static void FindAgainstUnavailableMicrosoftServer()
    {
        using var context = new MsAm.PrincipalContext(
            MsAm.ContextType.Domain,
            "127.0.0.1:1",
            "DC=unavailable",
            MsAm.ContextOptions.SimpleBind,
            "user",
            "password");
        _ = MsAm.UserPrincipal.FindByIdentity(context, "missing");
    }

    private static void FindAgainstUnavailableOurServer()
    {
        using var context = new OurAm.PrincipalContext(
            OurAm.ContextType.Domain,
            "127.0.0.1:1",
            "DC=unavailable",
            OurAm.ContextOptions.SimpleBind,
            "user",
            "password");
        _ = OurAm.UserPrincipal.FindByIdentity(context, "missing");
    }

    private static void CompareDuplicateDirectoryEntry(string name)
    {
        var dn = $"CN={name},{DifferentialSettings.BaseDn}";
        using var microsoftParent = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ourParent = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        using var first = microsoftParent.Children.Add($"CN={name}", "user");
        first.Properties["sAMAccountName"].Value = name;
        first.CommitChanges();

        try
        {
            using var microsoftDuplicate = microsoftParent.Children.Add($"CN={name}", "user");
            microsoftDuplicate.Properties["sAMAccountName"].Value = name;
            using var ourDuplicate = ourParent.Children.Add($"CN={name}", "user");
            ourDuplicate.Properties["sAMAccountName"].Value = name;

            AssertEquivalent(
                "duplicate DirectoryEntry",
                Record.Exception(microsoftDuplicate.CommitChanges),
                Record.Exception(ourDuplicate.CommitChanges));
        }
        finally
        {
            using var cleanup = new Ms.DirectoryEntry(
                DifferentialSettings.PathFor(dn),
                DifferentialSettings.BindDn,
                DifferentialSettings.BindPassword,
                DifferentialSettings.MicrosoftAuthenticationTypes);
            cleanup.DeleteTree();
        }
    }

    private static void CompareDuplicatePrincipal(string name)
    {
        using var microsoftContext = new MsAm.PrincipalContext(
            MsAm.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.BaseDn,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var ourContext = new OurAm.PrincipalContext(
            OurAm.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.BaseDn,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var first = new MsAm.UserPrincipal(microsoftContext)
        {
            Name = name,
            SamAccountName = name,
        };
        first.Save();

        try
        {
            using var microsoftDuplicate = new MsAm.UserPrincipal(microsoftContext)
            {
                Name = name,
                SamAccountName = name,
            };
            using var ourDuplicate = new OurAm.UserPrincipal(ourContext)
            {
                Name = name,
                SamAccountName = name,
            };

            AssertEquivalent(
                "duplicate principal",
                Record.Exception(microsoftDuplicate.Save),
                Record.Exception(ourDuplicate.Save));
        }
        finally
        {
            first.Delete();
        }
    }

    private static void AssertEquivalent(
        string operation,
        Exception? microsoft,
        Exception? ours)
    {
        Assert.NotNull(microsoft);
        Assert.NotNull(ours);
        new Comparison(operation)
            .Check("Type", microsoft.GetType().Name, ours.GetType().Name)
            .Check("HResult", microsoft.HResult, ours.HResult)
            .Assert();
    }
}
