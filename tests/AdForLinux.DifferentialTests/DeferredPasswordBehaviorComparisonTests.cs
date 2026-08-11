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
            DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer,
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

        Exception? msException;
        try
        {
            using var msUser = new Ms.UserPrincipal(msContext)
            {
                Name = msName,
                SamAccountName = msName,
                Enabled = false,
            };
            msUser.SetPassword("short");
            msException = Record.Exception(msUser.Save);
        }
        finally
        {
            DeleteMicrosoftUser(msContext, msName);
        }

        Exception? ourException;
        try
        {
            using var ourUser = new Ours.UserPrincipal(ourContext)
            {
                Name = ourName,
                SamAccountName = ourName,
                Enabled = false,
            };
            ourUser.SetPassword("short");
            ourException = Record.Exception(ourUser.Save);
        }
        finally
        {
            DeleteOurUser(ourContext, ourName);
        }

        Assert.Equal(msException?.GetType().Name, ourException?.GetType().Name);
        Assert.IsType<InvalidOperationException>(msException);
        Assert.IsType<InvalidOperationException>(ourException);
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
}
