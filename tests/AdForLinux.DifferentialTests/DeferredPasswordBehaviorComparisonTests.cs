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

            Assert.Equal(msException?.GetType().Name, ourException?.GetType().Name);
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
            Assert.Equal("Rollback retry", savedMicrosoft!.DisplayName);
            Assert.Equal(savedMicrosoft.DisplayName, savedOurs!.DisplayName);
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
            Assert.Equal(msException!.GetType().Name, ourException?.GetType().Name);
            Assert.Null(msGroup.DistinguishedName);
            Assert.Null(ourGroup.DistinguishedName);
            Assert.Equal(msGroupName, msGroup.Name);
            Assert.Equal(ourGroupName, ourGroup.Name);
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
        Assert.Equal(name, user.Name);
        Assert.Equal(name, user.SamAccountName);
        Assert.Equal("Rollback retry", user.DisplayName);
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
        Assert.Equal(name, user.Name);
        Assert.Equal(name, user.SamAccountName);
        Assert.Equal("Rollback retry", user.DisplayName);
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
