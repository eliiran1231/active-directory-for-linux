using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class DeferredPasswordBehaviorComparisonTests
{
    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.BaseDn,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.BaseDn,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    [Fact]
    public void Unassigned_enabled_with_flag_then_password_saves_like_microsoft() =>
        AssertUnassignedEnabledPasswordSave(passwordFirst: false);

    [Fact]
    public void Unassigned_enabled_with_password_then_flag_saves_like_microsoft() =>
        AssertUnassignedEnabledPasswordSave(passwordFirst: true);

    private static void AssertUnassignedEnabledPasswordSave(bool passwordFirst)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msName = $"d183-ms-{suffix}";
        var ourName = $"d183-our-{suffix}";
        const string password = "Str0ng!Passw0rd#2026";
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.UserPrincipal(msContext) { Name = msName, SamAccountName = msName };
        using var ours = new Ours.UserPrincipal(ourContext) { Name = ourName, SamAccountName = ourName };

        try
        {
            if (passwordFirst)
            {
                microsoft.SetPassword(password);
                ours.SetPassword(password);
            }

            microsoft.PasswordNeverExpires = ours.PasswordNeverExpires = true;
            if (!passwordFirst)
            {
                microsoft.SetPassword(password);
                ours.SetPassword(password);
            }

            Assert.Null(microsoft.Enabled);
            Assert.Null(ours.Enabled);
            var expectedError = Record.Exception(microsoft.Save);
            var actualError = Record.Exception(ours.Save);
            Assert.Null(expectedError);
            Assert.Null(actualError);

            using var savedMicrosoft = Ms.UserPrincipal.FindByIdentity(msContext, msName);
            using var savedOurs = Ours.UserPrincipal.FindByIdentity(ourContext, ourName);
            Assert.NotNull(savedMicrosoft);
            Assert.NotNull(savedOurs);
            Assert.Equal(SuiteCapture.Expected(savedMicrosoft.Enabled, "assert-equal-expected", 71), SuiteCapture.Expected(savedOurs.Enabled, "assert-equal-actual", 71));
            Assert.True(savedMicrosoft.PasswordNeverExpires);
            Assert.Equal(SuiteCapture.Expected(savedMicrosoft.PasswordNeverExpires, "assert-equal-expected", 73), SuiteCapture.Expected(savedOurs.PasswordNeverExpires, "assert-equal-actual", 73));
            Assert.NotNull(savedMicrosoft.LastPasswordSet);
            Assert.NotNull(savedOurs.LastPasswordSet);
        }
        finally
        {
            DeleteMicrosoftUser(msContext, msName);
            DeleteOurUser(ourContext, ourName);
        }
    }

    [Fact]
    public void Save_surfaces_a_rejected_deferred_password_like_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msName = $"adfl-ms-pw-{suffix}";
        var ourName = $"adfl-our-pw-{suffix}";

        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msUser = new Ms.UserPrincipal(msContext)
        {
            Name = msName,
            SamAccountName = msName,
            DisplayName = "Rollback retry",
            Enabled = false,
        };
        using var ourUser = new Ours.UserPrincipal(ourContext)
        {
            Name = ourName,
            SamAccountName = ourName,
            DisplayName = "Rollback retry",
            Enabled = false,
        };

        try
        {
            msUser.SetPassword("short");
            ourUser.SetPassword("short");

            var msException = Record.Exception(msUser.Save);
            var ourException = Record.Exception(ourUser.Save);

            Assert.Equal(SuiteCapture.Expected(msException?.GetType().Name, "assert-equal-expected", 117), SuiteCapture.Expected(ourException?.GetType().Name, "assert-equal-actual", 117));
            Assert.IsType<InvalidOperationException>(msException);
            Assert.IsType<InvalidOperationException>(ourException);

            AssertFailedUserState(msUser, msContext, msName);
            AssertFailedUserState(ourUser, ourContext, ourName);

            using var correctedMicrosoft = new Ms.UserPrincipal(msContext)
            {
                Name = msName,
                SamAccountName = msName,
                DisplayName = "Rollback retry",
                Enabled = false,
            };
            using var correctedOurs = new Ours.UserPrincipal(ourContext)
            {
                Name = ourName,
                SamAccountName = ourName,
                DisplayName = "Rollback retry",
                Enabled = false,
            };
            correctedMicrosoft.SetPassword("Str0ng!Passw0rd#2026");
            correctedOurs.SetPassword("Str0ng!Passw0rd#2026");
            correctedMicrosoft.Save();
            correctedOurs.Save();

            using var savedMicrosoft = Ms.UserPrincipal.FindByIdentity(msContext, msName);
            using var savedOurs = Ours.UserPrincipal.FindByIdentity(ourContext, ourName);
            Assert.NotNull(savedMicrosoft);
            Assert.NotNull(savedOurs);
            Assert.Equal(SuiteCapture.Expected("Rollback retry", "assert-equal-expected", 147), SuiteCapture.Expected(savedMicrosoft!.DisplayName, "assert-equal-actual", 147));
            Assert.Equal(SuiteCapture.Expected(savedMicrosoft.DisplayName, "assert-equal-expected", 148), SuiteCapture.Expected(savedOurs!.DisplayName, "assert-equal-actual", 148));
        }
        finally
        {
            DeleteMicrosoftUser(msContext, msName);
            DeleteOurUser(ourContext, ourName);
        }
    }

    [Fact]
    public void Failed_initial_group_membership_rolls_back_like_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msMemberName = $"adfl-mm-{suffix}";
        var ourMemberName = $"adfl-om-{suffix}";
        var msGroupName = $"adfl-mg-{suffix}";
        var ourGroupName = $"adfl-og-{suffix}";

        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msMember = new Ms.UserPrincipal(msContext)
        {
            Name = msMemberName,
            SamAccountName = msMemberName,
            Enabled = false,
        };
        using var ourMember = new Ours.UserPrincipal(ourContext)
        {
            Name = ourMemberName,
            SamAccountName = ourMemberName,
            Enabled = false,
        };
        using var msGroup = new Ms.GroupPrincipal(msContext, msGroupName);
        using var ourGroup = new Ours.GroupPrincipal(ourContext, ourGroupName);

        try
        {
            msMember.Save();
            ourMember.Save();
            msGroup.Members.Add(msMember);
            ourGroup.Members.Add(ourMember);
            DeleteMicrosoftObject($"CN={msMemberName},{DifferentialSettings.BaseDn}");
            DeleteOurObject($"CN={ourMemberName},{DifferentialSettings.BaseDn}");

            var msException = Record.Exception(msGroup.Save);
            var ourException = Record.Exception(ourGroup.Save);

            Assert.NotNull(msException);
            Assert.Equal(SuiteCapture.Expected(msException!.GetType().Name, "assert-equal-expected", 196), SuiteCapture.Expected(ourException?.GetType().Name, "assert-equal-actual", 196));
            Assert.Null(msGroup.DistinguishedName);
            Assert.Null(ourGroup.DistinguishedName);
            Assert.Equal(SuiteCapture.Expected(msGroupName, "assert-equal-expected", 199), SuiteCapture.Expected(msGroup.Name, "assert-equal-actual", 199));
            Assert.Equal(SuiteCapture.Expected(ourGroupName, "assert-equal-expected", 200), SuiteCapture.Expected(ourGroup.Name, "assert-equal-actual", 200));
            Assert.Null(Ms.GroupPrincipal.FindByIdentity(msContext, msGroupName));
            Assert.Null(Ours.GroupPrincipal.FindByIdentity(ourContext, ourGroupName));

            using var msReplacement = new Ms.UserPrincipal(msContext)
            {
                Name = msMemberName,
                SamAccountName = msMemberName,
                Enabled = false,
            };
            using var ourReplacement = new Ours.UserPrincipal(ourContext)
            {
                Name = ourMemberName,
                SamAccountName = ourMemberName,
                Enabled = false,
            };
            msReplacement.Save();
            ourReplacement.Save();
            using var correctedMicrosoft = new Ms.GroupPrincipal(msContext, msGroupName);
            using var correctedOurs = new Ours.GroupPrincipal(ourContext, ourGroupName);
            correctedMicrosoft.Members.Add(msReplacement);
            correctedOurs.Members.Add(ourReplacement);
            correctedMicrosoft.Save();
            correctedOurs.Save();

            using var savedMicrosoft = Ms.GroupPrincipal.FindByIdentity(msContext, msGroupName);
            using var savedOurs = Ours.GroupPrincipal.FindByIdentity(ourContext, ourGroupName);
            Assert.NotNull(savedMicrosoft);
            Assert.NotNull(savedOurs);
            Assert.True(savedMicrosoft!.Members.Contains(msReplacement));
            Assert.True(savedOurs!.Members.Contains(ourReplacement));
        }
        finally
        {
            DeleteMicrosoftGroup(msContext, msGroupName);
            DeleteOurGroup(ourContext, ourGroupName);
            DeleteMicrosoftUser(msContext, msMemberName);
            DeleteOurUser(ourContext, ourMemberName);
        }
    }

    private static void AssertFailedUserState(
        Ms.UserPrincipal user,
        Ms.PrincipalContext context,
        string name)
    {
        Assert.Null(Ms.UserPrincipal.FindByIdentity(context, name));
        Assert.Null(user.DistinguishedName);
        Assert.Null(user.Guid);
        Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 249), SuiteCapture.Expected(user.Name, "assert-equal-actual", 249));
        Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 250), SuiteCapture.Expected(user.SamAccountName, "assert-equal-actual", 250));
        Assert.Equal(SuiteCapture.Expected("Rollback retry", "assert-equal-expected", 251), SuiteCapture.Expected(user.DisplayName, "assert-equal-actual", 251));
        Assert.False(user.Enabled);
        using var groups = user.GetGroups();
        Assert.Empty(groups);
    }

    private static void AssertFailedUserState(
        Ours.UserPrincipal user,
        Ours.PrincipalContext context,
        string name)
    {
        Assert.Null(Ours.UserPrincipal.FindByIdentity(context, name));
        Assert.False(user.IsPersisted);
        Assert.Null(user.DistinguishedName);
        Assert.Null(user.Guid);
        Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 266), SuiteCapture.Expected(user.Name, "assert-equal-actual", 266));
        Assert.Equal(SuiteCapture.Expected(name, "assert-equal-expected", 267), SuiteCapture.Expected(user.SamAccountName, "assert-equal-actual", 267));
        Assert.Equal(SuiteCapture.Expected("Rollback retry", "assert-equal-expected", 268), SuiteCapture.Expected(user.DisplayName, "assert-equal-actual", 268));
        Assert.False(user.Enabled);
        using var groups = user.GetGroups();
        Assert.Empty(groups);
    }

    private static void DeleteMicrosoftUser(Ms.PrincipalContext context, string name)
    {
        try
        {
            using var user = Ms.UserPrincipal.FindByIdentity(context, name);
            user?.Delete();
        }
        catch (Ms.PrincipalException)
        {
            // Preserve the password-operation result when the store is unavailable.
        }
    }

    private static void DeleteOurUser(Ours.PrincipalContext context, string name)
    {
        try
        {
            using var user = Ours.UserPrincipal.FindByIdentity(context, name);
            user?.Delete();
        }
        catch (Ours.PrincipalException)
        {
            // Preserve the password-operation result when the store is unavailable.
        }
    }

    private static void DeleteMicrosoftGroup(Ms.PrincipalContext context, string name)
    {
        try
        {
            using var group = Ms.GroupPrincipal.FindByIdentity(context, name);
            group?.Delete();
        }
        catch (Ms.PrincipalException)
        {
        }
    }

    private static void DeleteOurGroup(Ours.PrincipalContext context, string name)
    {
        try
        {
            using var group = Ours.GroupPrincipal.FindByIdentity(context, name);
            group?.Delete();
        }
        catch (Ours.PrincipalException)
        {
        }
    }

    private static void DeleteMicrosoftObject(string distinguishedName)
    {
        using var entry = new System.DirectoryServices.DirectoryEntry(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        entry.DeleteTree();
    }

    private static void DeleteOurObject(string distinguishedName)
    {
        using var entry = new AdForLinux.DirectoryServices.DirectoryEntry(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);
        entry.DeleteTree();
    }
}
