using MsDs = System.DirectoryServices;
using Ms = System.DirectoryServices.AccountManagement;
using OursDs = AdForLinux.DirectoryServices;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PrincipalSaveContextComparisonTests
{
    [Fact]
    public void Saving_a_persisted_principal_to_another_container_matches_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var targetOuName = $"d134-{suffix}";
        var targetOuDn = $"OU={targetOuName},{DifferentialSettings.BaseDn}";
        var microsoftName = $"d134-ms-{suffix}";
        var ourName = $"d134-our-{suffix}";
        var microsoftSourceDn = $"CN={microsoftName},{DifferentialSettings.UsersContainer}";
        var ourSourceDn = $"CN={ourName},{DifferentialSettings.UsersContainer}";
        var microsoftTargetDn = $"CN={microsoftName},{targetOuDn}";
        var ourTargetDn = $"CN={ourName},{targetOuDn}";

        CreateMicrosoftOu(targetOuName);

        try
        {
            using var microsoftSource = MicrosoftContext(DifferentialSettings.UsersContainer);
            using var ourSource = OurContext(DifferentialSettings.UsersContainer);
            using var microsoftTarget = MicrosoftContext(targetOuDn);
            using var ourTarget = OurContext(targetOuDn);
            using var microsoft = new Ms.GroupPrincipal(microsoftSource, microsoftName);
            using var ours = new Ours.GroupPrincipal(ourSource, ourName);

            microsoft.Save();
            ours.Save();

            microsoft.Save(microsoftTarget);
            ours.Save(ourTarget);

            Assert.Same(microsoftTarget, microsoft.Context);
            Assert.Same(ourTarget, ours.Context);
            Assert.Equal(microsoftTargetDn, microsoft.DistinguishedName, ignoreCase: true);
            Assert.Equal(ourTargetDn, ours.DistinguishedName, ignoreCase: true);
            Assert.Equal(
                MicrosoftEntryExists(microsoftSourceDn),
                OurEntryExists(ourSourceDn));
            Assert.Equal(
                MicrosoftEntryExists(microsoftTargetDn),
                OurEntryExists(ourTargetDn));

            using var microsoftFromTarget = Ms.GroupPrincipal.FindByIdentity(
                microsoftTarget,
                Ms.IdentityType.SamAccountName,
                microsoftName);
            using var ourFromTarget = Ours.GroupPrincipal.FindByIdentity(
                ourTarget,
                Ours.IdentityType.SamAccountName,
                ourName);
            Assert.Equal(microsoftFromTarget is not null, ourFromTarget is not null);
        }
        finally
        {
            DeleteMicrosoftTreeIfPresent(microsoftSourceDn);
            DeleteOurTreeIfPresent(ourSourceDn);
            DeleteMicrosoftTreeIfPresent(targetOuDn);
        }
    }

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

    private static MsDs.DirectoryEntry OpenMicrosoft(string distinguishedName) =>
        new(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static OursDs.DirectoryEntry OpenOurs(string distinguishedName) =>
        new(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

    private static void CreateMicrosoftOu(string name)
    {
        using var parent = OpenMicrosoft(DifferentialSettings.BaseDn);
        using var child = parent.Children.Add($"OU={name}", "organizationalUnit");
        child.CommitChanges();
    }

    private static bool MicrosoftEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = OpenMicrosoft(distinguishedName);
            _ = entry.NativeGuid;
            return true;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    private static bool OurEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = OpenOurs(distinguishedName);
            _ = entry.NativeGuid;
            return true;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    private static void DeleteMicrosoftTreeIfPresent(string distinguishedName)
    {
        try
        {
            using var entry = OpenMicrosoft(distinguishedName);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Best effort cleanup for an object that may already have moved.
        }
    }

    private static void DeleteOurTreeIfPresent(string distinguishedName)
    {
        try
        {
            using var entry = OpenOurs(distinguishedName);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Best effort cleanup for an object that may already have moved.
        }
    }
}
