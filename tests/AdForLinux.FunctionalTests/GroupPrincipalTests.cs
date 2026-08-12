using System.Collections;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 9: create, change, and delete groups, and manage members, against
/// smblds. Each test cleans up what it makes.
/// </summary>
public class GroupPrincipalTests
{
    private static PrincipalContext Context() =>
        TestSettings.CreatePrincipalContext(TestDirectory.UsersContainer);

    private static string NewName() => $"adfl-g-{Guid.NewGuid():N}".Substring(0, 18);

    private static string DnFor(string cn) => $"CN={cn},{TestDirectory.UsersContainer}";

    private static string SeedUser(string name) =>
        TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

    [Fact]
    public void Save_creates_a_global_security_group_by_default()
    {
        var name = NewName();
        try
        {
            using (var context = Context())
            {
                using var group = new GroupPrincipal(context, name);
                group.Save();
                Assert.Equal(DnFor(name), group.DistinguishedName);
            }

            using var check = Context();
            var found = GroupPrincipal.FindByIdentity(check, name);
            Assert.NotNull(found);
            Assert.Equal(GroupScope.Global, found!.GroupScope);
            Assert.True(found.IsSecurityGroup);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(name));
        }
    }

    [Fact]
    public void GroupScope_and_IsSecurityGroup_round_trip()
    {
        var name = NewName();
        try
        {
            using var context = Context();
            using (var group = new GroupPrincipal(context, name))
            {
                group.GroupScope = GroupScope.Universal;
                group.IsSecurityGroup = false;   // a distribution group
                group.Save();
            }

            var found = GroupPrincipal.FindByIdentity(context, name);
            Assert.NotNull(found);
            Assert.Equal(GroupScope.Universal, found!.GroupScope);
            Assert.False(found.IsSecurityGroup);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(name));
        }
    }

    [Fact]
    public void Members_add_then_contains_and_count()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using (var group = new GroupPrincipal(context, groupName))
            {
                group.Save();

                var user = UserPrincipal.FindByIdentity(context, userName);
                Assert.NotNull(user);

                Assert.False(group.Members.Contains(user!));
                group.Members.Add(user!);
                group.Save();

                Assert.True(group.Members.Contains(user!));
                Assert.Equal(1, group.Members.Count);
                user!.Dispose();
            }

            // Confirm from a fresh read.
            var reread = GroupPrincipal.FindByIdentity(context, groupName);
            Assert.NotNull(reread);
            var members = reread!.Members.ToList();
            Assert.Single(members);
            Assert.Equal(userDn, members[0].DistinguishedName);
            foreach (var member in members)
            {
                member.Dispose();
            }

            reread.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Members_remove_takes_the_member_out()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();

            var user = UserPrincipal.FindByIdentity(context, userName);
            Assert.NotNull(user);

            group.Members.Add(user!);
            group.Save();
            Assert.Equal(1, group.Members.Count);

            group.Members.Remove(user!);
            group.Save();

            Assert.False(group.Members.Contains(user!));
            Assert.Equal(0, group.Members.Count);
            user!.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Members_enumerates_users_as_user_principals()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();

            var user = UserPrincipal.FindByIdentity(context, userName);
            group.Members.Add(user!);
            group.Save();
            user!.Dispose();

            var members = group.Members.ToList();
            Assert.Single(members);
            Assert.IsType<UserPrincipal>(members[0]);
            Assert.Equal(userName, members[0].SamAccountName);
            members[0].Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Nested_group_is_returned_as_a_group_principal()
    {
        var outerName = NewName();
        var innerName = NewName();

        try
        {
            using var context = Context();
            using var outer = new GroupPrincipal(context, outerName);
            outer.Save();

            using (var inner = new GroupPrincipal(context, innerName))
            {
                inner.Save();
                outer.Members.Add(inner);
                outer.Save();
            }

            var members = outer.Members.ToList();
            Assert.Single(members);
            Assert.IsType<GroupPrincipal>(members[0]);
            members[0].Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
            TestDirectory.Delete(DnFor(innerName));
        }
    }

    [Fact]
    public void Members_exposes_collection_surface_and_copy_validation()
    {
        using var context = Context();
        using var group = new GroupPrincipal(context, NewName());
        ICollection<Principal> generic = group.Members;
        ICollection nongeneric = group.Members;

        Assert.False(generic.IsReadOnly);
        Assert.False(nongeneric.IsSynchronized);
        Assert.Same(group.Members, nongeneric.SyncRoot);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            nongeneric.CopyTo(Array.Empty<Principal>(), -1));
        Assert.Throws<ArgumentNullException>(() =>
            nongeneric.CopyTo(null!, 0));
        Assert.Throws<ArgumentException>(() =>
            nongeneric.CopyTo(new Principal[1, 1], 0));
        Assert.Throws<ArgumentException>(() =>
            nongeneric.CopyTo(Array.Empty<Principal>(), 0));

        var destination = new Principal[1];
        generic.CopyTo(destination, 0);
        Assert.Null(destination[0]);
    }

    [Fact]
    public void Members_duplicate_add_throws_and_remove_non_member_returns_false()
    {
        var groupName = NewName();
        var memberName = NewName();
        var otherName = NewName();
        var memberDn = SeedUser(memberName);
        var otherDn = SeedUser(otherName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();
            using var member = UserPrincipal.FindByIdentity(context, memberName)!;
            using var other = UserPrincipal.FindByIdentity(context, otherName)!;

            group.Members.Add(member);
            Assert.Throws<PrincipalExistsException>(() => group.Members.Add(member));
            group.Save();
            Assert.Throws<PrincipalExistsException>(() => group.Members.Add(member));

            Assert.False(group.Members.Remove(other));
            Assert.False(group.Members.Contains(other));
            group.Save();
            Assert.True(group.Members.Contains(member));
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(memberDn);
            TestDirectory.Delete(otherDn);
        }
    }

    [Fact]
    public void Members_add_and_remove_cancel_before_save()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();
            using var user = UserPrincipal.FindByIdentity(context, userName)!;

            group.Members.Add(user);
            Assert.True(group.Members.Remove(user));
            Assert.False(group.Members.Contains(user));
            group.Save();

            using var reread = GroupPrincipal.FindByIdentity(context, groupName)!;
            Assert.False(reread.Members.Contains(user));
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Members_remove_and_add_cancel_before_save()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();
            using var user = UserPrincipal.FindByIdentity(context, userName)!;
            group.Members.Add(user);
            group.Save();

            Assert.True(group.Members.Remove(user));
            group.Members.Add(user);
            group.Save();

            using var reread = GroupPrincipal.FindByIdentity(context, groupName)!;
            Assert.True(reread.Members.Contains(user));
            Assert.Single(reread.Members);
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Members_multi_save_state_remains_consistent()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();
            using var user = UserPrincipal.FindByIdentity(context, userName)!;

            group.Members.Add(user);
            group.Save();
            Assert.True(group.Members.Remove(user));
            group.Members.Add(user);
            group.Save();
            Assert.True(group.Members.Contains(user));

            Assert.True(group.Members.Remove(user));
            group.Save();
            Assert.False(group.Members.Contains(user));

            group.Members.Add(user);
            group.Save();
            Assert.True(group.Members.Contains(user));
            Assert.Single(group.Members);
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Members_identity_overloads_match_lookup_behavior()
    {
        var groupName = NewName();
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var group = new GroupPrincipal(context, groupName);
            group.Save();

            Assert.False(group.Members.Contains(
                context, IdentityType.SamAccountName, "no-such-principal-xyz"));
            Assert.Throws<NoMatchingPrincipalException>(() => group.Members.Add(
                context, IdentityType.SamAccountName, "no-such-principal-xyz"));
            Assert.Throws<NoMatchingPrincipalException>(() => group.Members.Remove(
                context, IdentityType.SamAccountName, "no-such-principal-xyz"));

            group.Members.Add(context, IdentityType.SamAccountName, userName);
            Assert.True(group.Members.Contains(
                context, IdentityType.SamAccountName, userName));
            Assert.True(group.Members.Remove(
                context, IdentityType.SamAccountName, userName));
            Assert.False(group.Members.Contains(
                context, IdentityType.SamAccountName, userName));

            Assert.Throws<ArgumentNullException>(() => group.Members.Contains(
                null!, IdentityType.Name, userName));
            Assert.Throws<ArgumentNullException>(() => group.Members.Add(
                context, IdentityType.Name, null!));
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Primary_group_member_cannot_be_removed_or_cleared()
    {
        using var context = Context();
        using var group = GroupPrincipal.FindByIdentity(
            context, IdentityType.SamAccountName, "Domain Users");
        using var user = UserPrincipal.FindByIdentity(
            context, IdentityType.SamAccountName, "Administrator");

        Assert.NotNull(group);
        Assert.NotNull(user);
        Assert.True(group!.Members.Contains(user!));
        Assert.Throws<InvalidOperationException>(() => group.Members.Remove(user!));
        Assert.Throws<InvalidOperationException>(() => group.Members.Clear());
    }

    [Fact]
    public void Delete_removes_the_group()
    {
        var name = NewName();
        using var context = Context();
        using (var group = new GroupPrincipal(context, name))
        {
            group.Save();
            group.Delete();
        }

        Assert.Null(GroupPrincipal.FindByIdentity(context, name));
    }

    [Fact]
    public void FindByIdentity_returns_null_when_missing()
    {
        using var context = Context();

        Assert.Null(GroupPrincipal.FindByIdentity(context, "no-such-group-xyz-123"));
    }

    [Fact]
    public void Members_on_an_unsaved_group_is_empty()
    {
        using var context = Context();
        using var group = new GroupPrincipal(context, NewName());

        Assert.Empty(group.Members);
    }
}
