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
        TestSettings.CreatePrincipalContext(TestDirectory.UsersContainer);

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
    public void GetGroups_honors_the_query_context_container()
    {
        var userName = NewName();
        var insideName = NewName();
        var outsideName = NewName();
        var organizationalUnitName = NewName();
        var userDn = SeedUser(userName);
        var organizationalUnitDn = CreateOrganizationalUnit(organizationalUnitName);
        var insideDn = $"CN={insideName},{organizationalUnitDn}";
        var outsideDn = DnFor(outsideName);

        try
        {
            using (var insideContainer = new DirectoryEntry(
                TestSettings.PathFor(organizationalUnitDn),
                TestSettings.BindDn,
                TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer))
            using (var inside = insideContainer.Children.Add($"CN={insideName}", "group"))
            {
                inside.Properties["sAMAccountName"].Value = insideName;
                inside.Properties["member"].Add(userDn);
                inside.CommitChanges();
            }

            using (var users = new DirectoryEntry(
                TestSettings.PathFor(TestDirectory.UsersContainer),
                TestSettings.BindDn,
                TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer))
            using (var outside = users.Children.Add($"CN={outsideName}", "group"))
            {
                outside.Properties["sAMAccountName"].Value = outsideName;
                outside.Properties["member"].Add(userDn);
                outside.CommitChanges();
            }

            using var userContext = Context();
            using var scopedContext = TestSettings.CreatePrincipalContext(organizationalUnitDn);
            using var domainContext = TestSettings.CreatePrincipalContext();
            using var user = UserPrincipal.FindByIdentity(userContext, userName)!;

            using var scoped = user.GetGroups(scopedContext);
            var scopedNames = scoped.Select(group => group.SamAccountName).ToHashSet();
            Assert.Contains(insideName, scopedNames);
            Assert.DoesNotContain("Domain Users", scopedNames);
            Assert.DoesNotContain(outsideName, scopedNames);

            using var domainWide = user.GetGroups(domainContext);
            var domainNames = domainWide.Select(group => group.SamAccountName).ToHashSet();
            Assert.Contains(insideName, domainNames);
            Assert.Contains(outsideName, domainNames);
            Assert.Contains("Domain Users", domainNames);

            // The no-argument overload is constrained by the principal's own
            // explicitly configured context (CN=Users here).
            using var ownContext = user.GetGroups();
            Assert.Contains(outsideName, ownContext.Select(group => group.SamAccountName));
            Assert.DoesNotContain(insideName, ownContext.Select(group => group.SamAccountName));
            Assert.Contains("Domain Users", ownContext.Select(group => group.SamAccountName));
        }
        finally
        {
            TestDirectory.Delete(outsideDn);
            TestDirectory.Delete(insideDn);
            TestDirectory.Delete(organizationalUnitDn);
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

            // Verify tokenGroups independently from AccountManagement's group
            // traversal: every directory-backed token SID must be represented,
            // while well-known SIDs with no group object are intentionally absent.
            using var entry = new DirectoryEntry(
                TestSettings.PathFor(userDn),
                TestSettings.BindDn,
                TestSettings.BindPassword,
                AuthenticationTypes.SecureSocketsLayer);
            using var tokenSearcher = new DirectorySearcher(
                entry, "(objectClass=*)", new[] { "tokenGroups" }, SearchScope.Base);
            var tokenSids = tokenSearcher.FindOne()!.Properties["tokenGroups"]
                .Cast<object>()
                .OfType<byte[]>()
                .Select(SidCodec.Format)
                .ToList();
            using var baseContext = TestSettings.CreatePrincipalContext(TestSettings.BaseDn);
            var expectedDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var sid in tokenSids)
            {
                using var tokenGroup = GroupPrincipal.FindByIdentity(
                    baseContext, IdentityType.Sid, sid);
                if (tokenGroup?.DistinguishedName is not null)
                {
                    expectedDns.Add(tokenGroup.DistinguishedName);
                }
            }

            using var verified = user.GetAuthorizationGroups();
            Assert.True(expectedDns.SetEquals(
                verified.Select(group => group.DistinguishedName!)));
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
            using var specialContext = TestSettings.CreatePrincipalContext(specialOuDn);
            using var normalContext = TestSettings.CreatePrincipalContext(normalOuDn);
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
    public void GetMembers_recursive_handles_cycles_and_deduplicates_leaf_members()
    {
        var userName = NewName();
        var outerName = NewName();
        var leftName = NewName();
        var rightName = NewName();
        var userDn = SeedUser(userName);

        try
        {
            using var context = Context();
            using var outer = new GroupPrincipal(context, outerName);
            using var left = new GroupPrincipal(context, leftName);
            using var right = new GroupPrincipal(context, rightName);
            outer.Save();
            left.Save();
            right.Save();
            using var user = UserPrincipal.FindByIdentity(context, userName)!;

            left.Members.Add(user);
            left.Members.Add(outer); // outer -> left -> outer
            left.Save();
            right.Members.Add(user); // diamond duplicate
            right.Save();
            outer.Members.Add(left);
            outer.Members.Add(right);
            outer.Save();

            using var recursive = outer.GetMembers(recursive: true);
            Assert.Equal(new[] { userName }, recursive.Select(member => member.SamAccountName));
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
            TestDirectory.Delete(DnFor(leftName));
            TestDirectory.Delete(DnFor(rightName));
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void GetMembers_recursive_includes_primary_group_only_members_at_nested_levels()
    {
        var outerName = NewName();

        try
        {
            using var context = Context();
            using var outer = new GroupPrincipal(context, outerName);
            using var domainUsers = GroupPrincipal.FindByIdentity(
                context, IdentityType.SamAccountName, "Domain Users");
            outer.Save();
            Assert.NotNull(domainUsers);
            outer.Members.Add(domainUsers!);
            outer.Save();

            using var recursive = outer.GetMembers(recursive: true);
            var names = recursive.Select(member => member.SamAccountName).ToList();
            Assert.Contains("Administrator", names);
            Assert.DoesNotContain("Domain Users", names);
            Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }
        finally
        {
            TestDirectory.Delete(DnFor(outerName));
        }
    }

    [Fact]
    public void Administrator_is_in_domain_admins()
    {
        using var context = TestSettings.CreatePrincipalContext();

        var admin = UserPrincipal.FindByIdentity(context, "Administrator")!;
        using var groups = admin.GetGroups();

        Assert.Contains("Domain Admins", groups.Select(g => g.SamAccountName));
        admin.Dispose();
    }

    [Fact]
    public void GetGroups_on_an_unsaved_principal_matches_the_target_framework_contract()
    {
        using var context = Context();
        using var user = new UserPrincipal(context) { Name = NewName() };

        using var groups = user.GetGroups();
        Assert.Empty(groups);
        Assert.Throws<InvalidOperationException>(() => user.GetGroups(context));
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
            "(&(objectCategory=user)(objectClass=user)(sAMAccountName=jeff))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void PrincipalSearcher_without_a_query_filter_throws()
    {
        using var searcher = new PrincipalSearcher();

        Assert.Throws<InvalidOperationException>(() => searcher.FindOne());
    }
}
