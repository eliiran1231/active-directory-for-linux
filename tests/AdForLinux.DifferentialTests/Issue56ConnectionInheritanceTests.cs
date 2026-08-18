using System.DirectoryServices.Protocols;
using Xunit;
using Ours = AdForLinux.DirectoryServices;
using OursAm = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Exercises issue #56 against a Windows AD endpoint that requires the
/// Negotiate bind and its signing/sealing protections to survive child creation.
/// AD_BASE_DN must identify an isolated writable OU for this test.
/// </summary>
[Collection("differential")]
public class Issue56ConnectionInheritanceTests
{
    private const OursAm.ContextOptions ProtectedNegotiate =
        OursAm.ContextOptions.Negotiate |
        OursAm.ContextOptions.Signing |
        OursAm.ContextOptions.Sealing;

    [Fact]
    public void Direct_children_add_inherits_protected_negotiate_options()
    {
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var groupName = $"i56g{suffix}";
        using var context = CreateContext();
        using var parent = context.CreateDirectoryEntry(DifferentialSettings.BaseDn);
        using var group = parent.Children.Add($"CN={groupName}", "group");
        var groupCreated = false;

        try
        {
            var inherited = group.BuildOptions();
            Assert.Equal(AuthType.Negotiate, inherited.AuthenticationType);
            Assert.True(inherited.Signing);
            Assert.True(inherited.Sealing);

            group.Properties["sAMAccountName"].Value = groupName;
            group.CommitChanges();
            groupCreated = true;
        }
        finally
        {
            if (groupCreated)
            {
                group.DeleteTree();
            }
        }
    }

    [Fact]
    public void User_principal_save_inherits_protected_negotiate_options()
    {
        var userName = $"i56u{Guid.NewGuid():N}"[..16];
        using var context = CreateContext();
        using var user = new OursAm.UserPrincipal(context)
        {
            Name = userName,
            SamAccountName = userName,
        };
        var userCreated = false;

        try
        {
            user.Save();
            userCreated = true;
            Assert.Equal($"CN={userName},{DifferentialSettings.BaseDn}", user.DistinguishedName);
        }
        finally
        {
            if (userCreated)
            {
                user.Delete();
            }
        }
    }

    private static OursAm.PrincipalContext CreateContext()
    {
        Assert.StartsWith("OU=", DifferentialSettings.BaseDn, StringComparison.OrdinalIgnoreCase);
        return new OursAm.PrincipalContext(
            OursAm.ContextType.Domain,
            DifferentialSettings.ServerName,
            DifferentialSettings.BaseDn,
            ProtectedNegotiate,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
    }
}
