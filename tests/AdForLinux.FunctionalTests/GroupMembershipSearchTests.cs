using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 10: GetGroups, recursive GetAuthorizationGroups (LDAP_MATCHING_RULE_
/// IN_CHAIN), and PrincipalSearcher, against smblds.
/// </summary>
public class GroupMembershipSearchTests
{
    private static PrincipalContext Context() =>
        new(ContextType.Domain, TestSettings.ServerName, TestDirectory.UsersContainer,
            TestSettings.BindDn, TestSettings.BindPassword);

    private static string NewName() => $"adfl-m-{Guid.NewGuid():N}".Substring(0, 18);

    private static string DnFor(string cn) => $"CN={cn},{TestDirectory.UsersContainer}";

    private static string SeedUser(string name) =>
        TestDirectory.Create(name, "user", new Dictionary<string, string>
        {
            ["sAMAccountName"] = name,
        });

    private static string CreateOrganizationalUnit(string name)
    {
        var dn = $"OU={name},{TestSettings.BaseDn}";
        using var domain = new DirectoryEntry(
            TestSettings.PathFor(TestSettings.BaseDn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);
        using var organizationalUnit = domain.Children.Add($"OU={name}", "organizationalUnit");
        organizationalUnit.CommitChanges();
        return dn;
    }

    [Fact]
    public void GetGroups_returns_direct_groups_only()
    {
        var userName = NewName();
        var innerName = NewName();
        var outerName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();

            // outer contains inner; inner contains the user.
            using var inner = new GroupPrincipal(context, innerName);
            inner.Save();
            using var outer = new GroupPrincipal(context, outerName);
            outer.Save();

            var user = UserPrincipal.FindByIdentity(context, userName)!;
            inner.Members.Add(user);
            inner.Save();
            outer.Members.Add(inner);
            outer.Save();

            using var direct = user.GetGroups();
            var names = direct.Select(g => g.SamAccountName).ToList();

            Assert.Contains(innerName, names);
            Assert.DoesNotContain(outerName, names);  // only reachable by nesting
            user.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
            TestDirectory.Delete(DnFor(innerName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void GetAuthorizationGroups_follows_nesting()
    {
        var userName = NewName();
        var innerName = NewName();
        var outerName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();

            using var inner = new GroupPrincipal(context, innerName);
            inner.Save();
            using var outer = new GroupPrincipal(context, outerName);
            outer.Save();

            var user = UserPrincipal.FindByIdentity(context, userName)!;
            inner.Members.Add(user);
            inner.Save();
            outer.Members.Add(inner);
            outer.Save();

            using var all = user.GetAuthorizationGroups();
            var names = all.Select(g => g.SamAccountName).ToList();

            Assert.Contains(innerName, names);
            Assert.Contains(outerName, names);   // found through the nested group
            user.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
            TestDirectory.Delete(DnFor(innerName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void GetMembers_returns_direct_or_recursive_members()
    {
        var userName = NewName();
        var innerName = NewName();
        var outerName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var inner = new GroupPrincipal(context, innerName);
            inner.Save();
            using var outer = new GroupPrincipal(context, outerName);
            outer.Save();

            using var user = UserPrincipal.FindByIdentity(context, userName)!;
            inner.Members.Add(user);
            inner.Save();
            outer.Members.Add(inner);
            outer.Save();

            using var direct = outer.GetMembers();
            Assert.Equal(new[] { innerName }, direct.Select(p => p.SamAccountName));

            using var recursive = outer.GetMembers(recursive: true);
            var names = recursive.Select(p => p.SamAccountName).ToList();
            Assert.Contains(userName, names);
            Assert.DoesNotContain(innerName, names);
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
            TestDirectory.Delete(DnFor(innerName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void GetMembers_recursive_ignores_the_context_container()
    {
        var specialOuName = NewName();
        var normalOuName = NewName();
        var outerName = NewName();
        var innerName = NewName();
        var userName = NewName();
        var specialOuDn = CreateOrganizationalUnit(specialOuName);
        var normalOuDn = CreateOrganizationalUnit(normalOuName);
        var outerDn = $"CN={outerName},{specialOuDn}";
        var innerDn = $"CN={innerName},{normalOuDn}";
        var userDn = $"CN={userName},{normalOuDn}";

        try
        {
            using var specialContext = new PrincipalContext(
                ContextType.Domain, TestSettings.ServerName, specialOuDn,
                TestSettings.BindDn, TestSettings.BindPassword);
            using var normalContext = new PrincipalContext(
                ContextType.Domain, TestSettings.ServerName, normalOuDn,
                TestSettings.BindDn, TestSettings.BindPassword);
            using var outer = new GroupPrincipal(specialContext, outerName);
            using var inner = new GroupPrincipal(normalContext, innerName);
            using var user = new UserPrincipal(normalContext)
            {
                Name = userName,
                SamAccountName = userName,
            };

            outer.Save();
            inner.Save();
            user.Save();
            inner.Members.Add(user);
            inner.Save();
            outer.Members.Add(inner);
            outer.Save();

            using var members = outer.GetMembers(recursive: true);
            Assert.Equal(new[] { userName }, members.Select(member => member.SamAccountName));
        }
        finally
        {
            TestDirectory.Delete(outerDn);
            TestDirectory.Delete(innerDn);
            TestDirectory.Delete(userDn);
            TestDirectory.Delete(specialOuDn);
            TestDirectory.Delete(normalOuDn);
        }
    }

    [Fact]
    public void Administrator_is_in_domain_admins()
    {
        using var context = new PrincipalContext(
            ContextType.Domain, TestSettings.ServerName, null,
            TestSettings.BindDn, TestSettings.BindPassword);

        var admin = UserPrincipal.FindByIdentity(context, "Administrator")!;
        using var groups = admin.GetGroups();

        Assert.Contains("Domain Admins", groups.Select(g => g.SamAccountName));
        admin.Dispose();
    }

    [Fact]
    public void GetGroups_on_an_unsaved_principal_is_empty()
    {
        using var context = Context();
        using var user = new UserPrincipal(context) { Name = NewName() };

        using var groups = user.GetGroups();
        Assert.Empty(groups);
    }

    [Fact]
    public void PrincipalSearcher_finds_a_user_by_sam_account_name()
    {
        var userName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var searcher = new PrincipalSearcher(
                new UserPrincipal(context) { SamAccountName = userName });

            var found = searcher.FindOne();

            Assert.NotNull(found);
            Assert.IsType<UserPrincipal>(found);
            Assert.Equal(userName, found!.SamAccountName);
            found.Dispose();
        }
        finally
        {
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void PrincipalSearcher_supports_a_wildcard()
    {
        var prefix = $"adfl-w{Guid.NewGuid():N}".Substring(0, 12);
        var first = $"{prefix}a";
        var second = $"{prefix}b";
        var firstDn = SeedUser(first);
        var secondDn = SeedUser(second);

        try
        {
            using var context = Context();
            using var searcher = new PrincipalSearcher(
                new UserPrincipal(context) { SamAccountName = $"{prefix}*" });

            using var found = searcher.FindAll();
            var names = found.Select(p => p.SamAccountName).ToList();

            Assert.Equal(2, names.Count);
            Assert.Contains(first, names);
            Assert.Contains(second, names);
        }
        finally
        {
            TestDirectory.Delete(firstDn);
            TestDirectory.Delete(secondDn);
        }
    }

    [Fact]
    public void PrincipalSearcher_finds_groups_when_the_example_is_a_group()
    {
        var groupName = NewName();

        try
        {
            using var context = Context();
            using (var group = new GroupPrincipal(context, groupName))
            {
                group.Save();
            }

            using var searcher = new PrincipalSearcher(
                new GroupPrincipal(context) { SamAccountName = groupName });

            var found = searcher.FindOne();

            Assert.NotNull(found);
            Assert.IsType<GroupPrincipal>(found);
            found!.Dispose();
        }
        finally
        {
            TestDirectory.Delete(DnFor(groupName));
        }
    }

    [Fact]
    public void PrincipalSearcher_builds_the_expected_filter()
    {
        using var context = Context();
        using var searcher = new PrincipalSearcher(
            new UserPrincipal(context) { SamAccountName = "jeff" });

        Assert.Equal(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=jeff))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void PrincipalSearcher_without_a_query_filter_throws()
    {
        using var searcher = new PrincipalSearcher();

        Assert.Throws<InvalidOperationException>(() => searcher.FindOne());
    }
}
