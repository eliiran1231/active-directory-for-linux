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
    public void CopyTo_creates_committed_copies_and_skips_server_managed_attributes()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sourceParentDn = $"OU=adfl-copy-source-{suffix},{TestSettings.BaseDn}";
        var destinationParentDn = $"OU=adfl-copy-target-{suffix},{TestSettings.BaseDn}";
        var sourceDn = $"OU=original,{sourceParentDn}";
        var explicitNullSourceDn = $"OU=explicit-null,{sourceParentDn}";
        var sameNameCopyDn = $"OU=original,{destinationParentDn}";
        var explicitNullCopyDn = $"OU=explicit-null,{destinationParentDn}";
        var renamedCopyDn = $"OU=renamed,{destinationParentDn}";
        var sourceUserDn = $"CN=source-user,{sourceParentDn}";
        var copiedUserDn = $"CN=copied-user,{destinationParentDn}";
        using var domain = Open(TestSettings.BaseDn);

        try
        {
            using (var sourceParent = domain.Children.Add($"OU=adfl-copy-source-{suffix}", "organizationalUnit"))
            using (var destinationParent = domain.Children.Add($"OU=adfl-copy-target-{suffix}", "organizationalUnit"))
            {
                sourceParent.CommitChanges();
                destinationParent.CommitChanges();
            }

            using (var sourceParent = Open(sourceParentDn))
            using (var source = sourceParent.Children.Add("OU=original", "organizationalUnit"))
            {
                source.Properties["description"].Value = "managed CopyTo fallback";
                source.Properties["telephoneNumber"].Value = "+1 555 0100";
                source.CommitChanges();
            }

            using (var sourceParent = Open(sourceParentDn))
            using (var source = sourceParent.Children.Add("OU=explicit-null", "organizationalUnit"))
            {
                source.Properties["description"].Value = "managed CopyTo explicit null";
                source.CommitChanges();
            }

            using (var sourceParent = Open(sourceParentDn))
            using (var sourceUser = sourceParent.Children.Add("CN=source-user", "user"))
            {
                sourceUser.Properties["sAMAccountName"].Value = $"cp{suffix}";
                sourceUser.Properties["description"].Value = "copied user property";
                sourceUser.CommitChanges();
            }

            using var openedSource = Open(sourceDn);
            using var destinationParentEntry = Open(destinationParentDn);
            using var sameNameCopy = openedSource.CopyTo(destinationParentEntry);
            using var explicitNullSource = Open(explicitNullSourceDn);
            using var explicitNullCopy = explicitNullSource.CopyTo(destinationParentEntry, null);
            using var renamedCopy = openedSource.CopyTo(destinationParentEntry, "OU=renamed");
            using var reopenedSameNameCopy = Open(sameNameCopyDn);
            using var reopenedExplicitNullCopy = Open(explicitNullCopyDn);
            using var reopenedRenamedCopy = Open(renamedCopyDn);
            using var openedSourceUser = Open(sourceUserDn);
            using var copiedUser = openedSourceUser.CopyTo(destinationParentEntry, "CN=copied-user");
            using var reopenedCopiedUser = Open(copiedUserDn);

            Assert.Equal(sameNameCopyDn, sameNameCopy.DistinguishedName);
            Assert.Equal(explicitNullCopyDn, explicitNullCopy.DistinguishedName);
            Assert.Equal(renamedCopyDn, renamedCopy.DistinguishedName);
            Assert.Equal("managed CopyTo fallback", reopenedSameNameCopy.Properties["description"].Value);
            Assert.Equal("managed CopyTo explicit null", reopenedExplicitNullCopy.Properties["description"].Value);
            Assert.Equal("+1 555 0100", reopenedRenamedCopy.Properties["telephoneNumber"].Value);
            Assert.NotEqual(openedSource.Guid, reopenedSameNameCopy.Guid);
            Assert.NotEqual(openedSource.Guid, reopenedRenamedCopy.Guid);
            Assert.Equal("copied user property", reopenedCopiedUser.Properties["description"].Value);
            Assert.NotEqual(
                openedSourceUser.Properties["sAMAccountName"].Value,
                reopenedCopiedUser.Properties["sAMAccountName"].Value);
        }
        finally
        {
            SafeDelete(sourceParentDn);
            SafeDelete(destinationParentDn);
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
        Assert.Throws<DirectoryServicesCOMException>(
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

            var error = Assert.Throws<DirectoryServicesCOMException>(
                () => domain.Children.Remove(parent));

            Assert.Equal(unchecked((int)0x80072015), error.ErrorCode);
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

            var error = Assert.Throws<DirectoryServicesCOMException>(
                () => first.Children.Remove(child));

            Assert.Equal(unchecked((int)0x80072030), error.ErrorCode);
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

    [Fact]
    public void Value_type_array_is_immediately_written_as_individual_values()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var name = $"adfl-arr-{suffix}";
        var dn = $"CN={name},{UsersContainer}";
        using var parent = Open(UsersContainer);

        try
        {
            using var child = parent.Children.Add($"CN={name}", "user");
            child.Properties["sAMAccountName"].Value = name;
            child.CommitChanges();
            child.UsePropertyCache = false;

            child.Properties["otherTelephone"].Value = new[] { 101, 202 };

            using var reopened = Open(dn);
            Assert.Equal(
                new[] { "101", "202" },
                reopened.Properties["otherTelephone"].Cast<string>().Order());
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
        var error = Assert.Throws<DirectoryServicesCOMException>(() => entry.RefreshCache());
        Assert.Equal(unchecked((int)0x80072030), error.ErrorCode);
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
