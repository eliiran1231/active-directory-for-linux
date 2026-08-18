using AdForLinux.DirectoryServices;
using System.DirectoryServices.Protocols;
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
    public void Multi_valued_mutations_preserve_concurrent_changes_and_use_distinct_operations()
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        var groupName = $"adfl-delta-g-{suffix}";
        var groupDn = $"CN={groupName},{TestSettings.BaseDn}";
        var memberDns = Enumerable.Range(0, 4)
            .Select(index => $"CN=adfl-d-{suffix}-{index},{TestSettings.BaseDn}")
            .ToArray();

        try
        {
            using var container = Open(TestSettings.BaseDn);
            for (var index = 0; index < memberDns.Length; index++)
            {
                using var member = container.Children.Add($"CN=adfl-d-{suffix}-{index}", "user");
                member.Properties["sAMAccountName"].Value = $"d{suffix}{index}";
                member.CommitChanges();
            }

            using (var group = container.Children.Add($"CN={groupName}", "group"))
            {
                group.Properties["sAMAccountName"].Value = groupName;
                group.Properties["member"].AddRange(memberDns[..2]);
                group.CommitChanges();
            }

            using (var first = Open(groupDn))
            using (var second = Open(groupDn))
            {
                _ = first.Properties["member"].Count;
                _ = second.Properties["member"].Count;
                first.Properties["member"].Add(memberDns[2]);
                first.CommitChanges();
                second.Properties["member"].Add(memberDns[3]);
                second.CommitChanges();
            }

            AssertMembers(groupDn, memberDns);

            using (var group = Open(groupDn))
            {
                group.Properties["member"].Remove(memberDns[0]);
                group.CommitChanges();
            }

            AssertMembers(groupDn, memberDns[1..]);

            using (var group = Open(groupDn))
            {
                group.Properties["member"].Value = memberDns[..2];
                group.CommitChanges();
            }

            AssertMembers(groupDn, memberDns[..2]);

            using (var group = Open(groupDn))
            {
                group.Properties["member"].Clear();
                group.CommitChanges();
            }

            AssertMembers(groupDn, Array.Empty<string>());
        }
        finally
        {
            SafeDelete(groupDn);
            foreach (var memberDn in memberDns)
            {
                SafeDelete(memberDn);
            }
        }
    }

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

    [Fact]
    public void Children_remove_deletes_an_empty_child()
    {
        var name = $"adfl-ou-{Guid.NewGuid():N}";
        var dn = $"OU={name},{TestSettings.BaseDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using var child = domain.Children.Add($"OU={name}", "organizationalUnit");
            child.CommitChanges();

            domain.Children.Remove(child);

            AssertMissing(dn);
        }
        finally
        {
            SafeDelete(dn);
        }
    }

    [Fact]
    public void Children_remove_handles_an_rdn_ending_in_a_literal_backslash()
    {
        var value = $"adfl-ou-{Guid.NewGuid():N}";
        var relativeName = $@"OU={value}\\";
        var dn = $"{relativeName},{TestSettings.BaseDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using var child = domain.Children.Add(relativeName, "organizationalUnit");
            child.CommitChanges();

            Assert.Equal(relativeName, child.Name);
            domain.Children.Remove(child);

            AssertMissing(dn);
        }
        finally
        {
            SafeDelete(dn);
        }
    }

    [Fact]
    public void Children_remove_does_not_recursively_delete_a_populated_child()
    {
        var parentName = $"adfl-ou-{Guid.NewGuid():N}";
        var childName = $"adfl-ou-{Guid.NewGuid():N}";
        var parentDn = $"OU={parentName},{TestSettings.BaseDn}";
        var childDn = $"OU={childName},{parentDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using var parent = domain.Children.Add($"OU={parentName}", "organizationalUnit");
            parent.CommitChanges();
            using var child = parent.Children.Add($"OU={childName}", "organizationalUnit");
            child.CommitChanges();

            var error = Assert.Throws<DirectoryOperationException>(
                () => domain.Children.Remove(parent));

            Assert.Equal(ResultCode.NotAllowedOnNonLeaf, error.Response.ResultCode);
            AssertExists(parentDn);
            AssertExists(childDn);
        }
        finally
        {
            SafeDelete(parentDn);
        }
    }

    [Fact]
    public void DeleteTree_remains_recursive_for_a_populated_child()
    {
        var parentName = $"adfl-ou-{Guid.NewGuid():N}";
        var childName = $"adfl-ou-{Guid.NewGuid():N}";
        var parentDn = $"OU={parentName},{TestSettings.BaseDn}";
        var childDn = $"OU={childName},{parentDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using var parent = domain.Children.Add($"OU={parentName}", "organizationalUnit");
            parent.CommitChanges();
            using var child = parent.Children.Add($"OU={childName}", "organizationalUnit");
            child.CommitChanges();

            parent.DeleteTree();

            AssertMissing(parentDn);
            AssertMissing(childDn);
        }
        finally
        {
            SafeDelete(parentDn);
        }
    }

    [Fact]
    public void Children_remove_uses_the_collections_parent()
    {
        var firstName = $"adfl-ou-{Guid.NewGuid():N}";
        var secondName = $"adfl-ou-{Guid.NewGuid():N}";
        var childName = $"adfl-ou-{Guid.NewGuid():N}";
        var firstDn = $"OU={firstName},{TestSettings.BaseDn}";
        var secondDn = $"OU={secondName},{TestSettings.BaseDn}";
        var childDn = $"OU={childName},{secondDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using var first = domain.Children.Add($"OU={firstName}", "organizationalUnit");
            first.CommitChanges();
            using var second = domain.Children.Add($"OU={secondName}", "organizationalUnit");
            second.CommitChanges();
            using var child = second.Children.Add($"OU={childName}", "organizationalUnit");
            child.CommitChanges();

            var error = Assert.Throws<DirectoryOperationException>(
                () => first.Children.Remove(child));

            Assert.Equal(ResultCode.NoSuchObject, error.Response.ResultCode);
            AssertExists(childDn);
        }
        finally
        {
            SafeDelete(firstDn);
            SafeDelete(secondDn);
        }
    }

    [Fact]
    public void Rename_updates_the_entry_path_and_preserves_properties()
    {
        var oldName = $"adfl-grp-{Guid.NewGuid():N}";
        var newName = $"adfl-grp-{Guid.NewGuid():N}";
        var newDn = $"CN={newName},{UsersContainer}";
        using var parent = Open(UsersContainer);

        try
        {
            using var child = parent.Children.Add($"CN={oldName}", "group");
            child.Properties["sAMAccountName"].Value = oldName;
            child.CommitChanges();

            child.Rename($"CN={newName}");

            Assert.Equal(newDn, child.DistinguishedName);
            Assert.Equal(newName, child.Properties["cn"].Value);

            using var reopened = Open(newDn);
            Assert.Equal(oldName, reopened.Properties["sAMAccountName"].Value);
        }
        finally
        {
            SafeDelete(newDn);
        }
    }

    [Fact]
    public void Disabling_property_cache_writes_changes_immediately()
    {
        var name = $"adfl-grp-{Guid.NewGuid():N}";
        var dn = $"CN={name},{UsersContainer}";
        using var parent = Open(UsersContainer);

        try
        {
            using var child = parent.Children.Add($"CN={name}", "group");
            child.Properties["sAMAccountName"].Value = name;
            child.CommitChanges();
            child.UsePropertyCache = false;

            child.Properties["description"].Value = "written without CommitChanges";

            using var reopened = Open(dn);
            Assert.Equal("written without CommitChanges", reopened.Properties["description"].Value);
        }
        finally
        {
            SafeDelete(dn);
        }
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

    private static void AssertExists(string dn)
    {
        using var entry = Open(dn);
        entry.RefreshCache();
    }

    private static void AssertMissing(string dn)
    {
        using var entry = Open(dn);
        var error = Assert.Throws<DirectoryOperationException>(() => entry.RefreshCache());
        Assert.Equal(ResultCode.NoSuchObject, error.Response.ResultCode);
    }

    private static void AssertMembers(string groupDn, IEnumerable<string> expected)
    {
        using var group = Open(groupDn);
        Assert.Equal(
            expected.OrderBy(value => value, StringComparer.OrdinalIgnoreCase),
            group.Properties["member"].Cast<string>()
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);
    }
}
