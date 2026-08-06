using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 5: create, modify, and delete objects with DirectoryEntry against
/// smblds. Each test cleans up the object it makes.
/// </summary>
public class DirectoryEntryWriteTests
{
    private static DirectoryEntry Open(string dn) =>
        new(TestSettings.PathFor(dn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    private static string UsersContainer => $"CN=Users,{TestSettings.BaseDn}";

    [Fact]
    public void Children_add_creates_an_object()
    {
        var name = $"adfl-grp-{Guid.NewGuid():N}";
        var dn = $"CN={name},{UsersContainer}";
        using var parent = Open(UsersContainer);

        try
        {
            var child = parent.Children.Add($"CN={name}", "group");
            child.Properties["sAMAccountName"].Value = name;
            child.CommitChanges();
            child.Dispose();

            using var reopened = Open(dn);
            Assert.Equal(name, reopened.Properties["sAMAccountName"].Value);
            Assert.Equal("group", reopened.SchemaClassName);
        }
        finally
        {
            SafeDelete(dn);
        }
    }

    [Fact]
    public void CommitChanges_updates_a_changed_property()
    {
        var name = $"adfl-grp-{Guid.NewGuid():N}";
        var dn = $"CN={name},{UsersContainer}";
        using var parent = Open(UsersContainer);

        try
        {
            var child = parent.Children.Add($"CN={name}", "group");
            child.Properties["sAMAccountName"].Value = name;
            child.CommitChanges();

            // Change one property on the existing object.
            child.Properties["description"].Value = "hello from adforlinux";
            child.CommitChanges();
            child.Dispose();

            using var reopened = Open(dn);
            Assert.Equal("hello from adforlinux", reopened.Properties["description"].Value);
        }
        finally
        {
            SafeDelete(dn);
        }
    }

    [Fact]
    public void DeleteTree_removes_the_object()
    {
        var name = $"adfl-grp-{Guid.NewGuid():N}";
        var dn = $"CN={name},{UsersContainer}";
        using var parent = Open(UsersContainer);

        var child = parent.Children.Add($"CN={name}", "group");
        child.Properties["sAMAccountName"].Value = name;
        child.CommitChanges();
        child.DeleteTree();
        child.Dispose();

        // Reading a deleted object should fail.
        using var reopened = Open(dn);
        Assert.Throws<System.DirectoryServices.Protocols.DirectoryOperationException>(
            () => _ = reopened.Properties["sAMAccountName"].Value);
    }

    private static void SafeDelete(string dn)
    {
        try
        {
            using var entry = Open(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup.
        }
    }
}
