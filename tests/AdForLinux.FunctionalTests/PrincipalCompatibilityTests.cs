using System.ComponentModel;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class PrincipalCompatibilityTests
{
    public sealed class ExtendedUserPrincipal : UserPrincipal
    {
        public ExtendedUserPrincipal(PrincipalContext context)
            : base(context)
        {
        }

        public object?[] ReadExtension(string attribute) => ExtensionGet(attribute);

        public void WriteExtension(string attribute, object? value) => ExtensionSet(attribute, value);

        public static ExtendedUserPrincipal? Find(PrincipalContext context, string identity) =>
            (ExtendedUserPrincipal?)FindByIdentityWithType(
                context, typeof(ExtendedUserPrincipal), identity);
    }

    private static PrincipalContext Context(string? container = null) =>
        TestSettings.CreatePrincipalContext(container ?? TestDirectory.UsersContainer);

    private static PrincipalContext OfflineContext() =>
        new(ContextType.Domain, "dc.example.test", "DC=example,DC=test");

    private static string NewName() => $"adfl-p-{Guid.NewGuid():N}"[..18];

    private static string DnFor(string cn, string container) => $"CN={cn},{container}";

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
    public void Extension_members_stage_values_and_validate_collections()
    {
        using var context = OfflineContext();
        using var user = new ExtendedUserPrincipal(context);

        Assert.Empty(user.ReadExtension("telephoneNumber"));
        user.WriteExtension("telephoneNumber", new object[] { "one", "two" });

        Assert.Equal(new object[] { "one", "two" }, user.ReadExtension("telephoneNumber"));
        Assert.Throws<ArgumentException>(() => user.WriteExtension("telephoneNumber", Array.Empty<object>()));
        Assert.Throws<ArgumentException>(() => user.WriteExtension(null!, "value"));

        var collection = new List<string> { "one", "two" };
        user.WriteExtension("otherTelephone", collection);
        var staged = user.ReadExtension("otherTelephone");
        Assert.Single(staged);
        Assert.Same(collection, staged[0]);
    }

    [Fact]
    public void Disposed_principals_reject_new_operations_before_argument_validation()
    {
        using var context = OfflineContext();
        var user = new UserPrincipal(context);
        user.Dispose();

        Assert.Throws<ObjectDisposedException>(() => user.Save());
        Assert.Throws<ObjectDisposedException>(() => user.Save(null!));
        Assert.Throws<ObjectDisposedException>(() => user.GetGroups());
        Assert.Throws<ObjectDisposedException>(() => user.IsMemberOf((GroupPrincipal)null!));
        Assert.Throws<ObjectDisposedException>(() => user.GetUnderlyingObject());
    }

    [Fact]
    public void Principal_surface_validates_arguments_before_connecting()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);

        Assert.Throws<InvalidOperationException>(() => user.Save(null!));
        Assert.Throws<ArgumentNullException>(() => Principal.FindByIdentity(null!, "user"));
        Assert.Throws<ArgumentNullException>(() => Principal.FindByIdentity(context, null!));
        Assert.Throws<InvalidEnumArgumentException>(() =>
            Principal.FindByIdentity(context, (IdentityType)99, "user"));
        Assert.Throws<ArgumentNullException>(() => user.GetGroups(null!));
        Assert.Throws<ArgumentNullException>(() => user.IsMemberOf((GroupPrincipal)null!));
    }

    [Fact]
    public void PrincipalSearcher_exposes_and_reuses_the_underlying_directory_searcher()
    {
        using var context = OfflineContext();
        using var filter = new UserPrincipal(context) { SamAccountName = "user*" };
        using var searcher = new PrincipalSearcher(filter);

        Assert.Equal(typeof(DirectorySearcher), searcher.GetUnderlyingSearcherType());
        var underlying = Assert.IsType<DirectorySearcher>(searcher.GetUnderlyingSearcher());
        Assert.Equal(256, underlying.PageSize);
        Assert.Equal(TimeSpan.FromSeconds(30), underlying.ServerTimeLimit);
        Assert.Equal(searcher.GetLdapFilter(), underlying.Filter);

        underlying.PageSize = 17;
        Assert.Same(underlying, searcher.GetUnderlyingSearcher());
        Assert.Equal(17, underlying.PageSize);
    }

    [Fact]
    public void PrincipalSearcher_uses_caller_changes_to_the_underlying_searcher()
    {
        using var context = Context();
        using var filter = new UserPrincipal(context) { SamAccountName = "Administrator" };
        using var searcher = new PrincipalSearcher(filter);
        var underlying = Assert.IsType<DirectorySearcher>(searcher.GetUnderlyingSearcher());
        underlying.PageSize = 1;
        underlying.SizeLimit = 1;

        using var results = searcher.FindAll();

        Assert.Single(results);
        Assert.Equal(1, underlying.PageSize);
        Assert.Equal(1, underlying.SizeLimit);
    }

    [Fact]
    public void PrincipalSearcher_rejects_persisted_query_filters()
    {
        var groupName = NewName();
        var groupDn = DnFor(groupName, TestDirectory.UsersContainer);

        try
        {
            using var context = Context();
            using var persisted = new GroupPrincipal(context, groupName);
            persisted.Save();

            Assert.Throws<ArgumentException>(() => new PrincipalSearcher(persisted));
            using var searcher = new PrincipalSearcher();
            Assert.Throws<ArgumentException>(() => searcher.QueryFilter = persisted);
        }
        finally
        {
            TestDirectory.Delete(groupDn);
        }
    }

    [Fact]
    public void PrincipalSearcher_rechecks_filter_persistence_before_searching()
    {
        var groupName = NewName();
        var groupDn = DnFor(groupName, TestDirectory.UsersContainer);

        try
        {
            using var context = Context();
            using var filter = new GroupPrincipal(context, groupName);
            using var searcher = new PrincipalSearcher(filter);
            filter.Save();

            Assert.Equal(typeof(DirectorySearcher), searcher.GetUnderlyingSearcherType());
            Assert.Throws<InvalidOperationException>(() => searcher.GetLdapFilter());
            Assert.Throws<InvalidOperationException>(() => searcher.GetUnderlyingSearcher());
            Assert.Throws<InvalidOperationException>(() => searcher.FindOne());
            Assert.Throws<InvalidOperationException>(() => searcher.FindAll());
        }
        finally
        {
            TestDirectory.Delete(groupDn);
        }
    }

    [Fact]
    public void Principal_identity_sid_extensions_groups_and_membership_round_trip()
    {
        var userName = NewName();
        var groupName = NewName();
        var userDn = DnFor(userName, TestDirectory.UsersContainer);
        var groupDn = DnFor(groupName, TestDirectory.UsersContainer);

        try
        {
            using var context = Context();
            using (var user = new ExtendedUserPrincipal(context)
            {
                Name = userName,
                SamAccountName = userName,
            })
            {
                user.WriteExtension("telephoneNumber", "12345");
                user.Save();
            }

            using var group = new GroupPrincipal(context, groupName);
            group.Save();
            using var found = ExtendedUserPrincipal.Find(context, userName);
            Assert.NotNull(found);
            Assert.Equal(new object[] { "12345" }, found!.ReadExtension("telephoneNumber"));

            group.Members.Add(found);
            group.Save();

            Assert.True(found.IsMemberOf(group));
            Assert.True(found.IsMemberOf(context, IdentityType.SamAccountName, groupName));
            using var groups = found.GetGroups(context);
            Assert.Contains(groupName, groups.Select(item => item.SamAccountName));

            using var untyped = Principal.FindByIdentity(context, userName);
            Assert.IsType<UserPrincipal>(untyped);
            Assert.NotNull(untyped!.SidValue);
            if (OperatingSystem.IsWindows())
            {
                Assert.NotNull(untyped.Sid);
            }
            else
            {
                Assert.Throws<PlatformNotSupportedException>(() => untyped.Sid);
            }

            Assert.Equal(found, untyped);

            using var byGuid = Principal.FindByIdentity(
                context, IdentityType.Guid, found.Guid!.Value.ToString());
            Assert.Equal(found, byGuid);

            using var bySid = Principal.FindByIdentity(
                context, IdentityType.Sid, found.SidValue!);
            Assert.Equal(found, bySid);
        }
        finally
        {
            TestDirectory.Delete(groupDn);
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Primary_group_counts_for_groups_and_membership()
    {
        var userName = NewName();
        var userDn = DnFor(userName, TestDirectory.UsersContainer);

        try
        {
            using var context = Context();
            using (var user = new UserPrincipal(context)
            {
                Name = userName,
                SamAccountName = userName,
            })
            {
                user.Save();
            }

            using var found = UserPrincipal.FindByIdentity(context, userName);
            using var domainUsers = GroupPrincipal.FindByIdentity(
                context, IdentityType.SamAccountName, "Domain Users");
            Assert.NotNull(found);
            Assert.NotNull(domainUsers);

            using var groups = found!.GetGroups();
            Assert.Contains(
                domainUsers!.DistinguishedName,
                groups.Select(group => group.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);
            Assert.True(found.IsMemberOf(domainUsers));
            Assert.True(found.IsMemberOf(
                context, IdentityType.SamAccountName, "Domain Users"));

            using (var entry = new DirectoryEntry(
                       TestSettings.PathFor(domainUsers.DistinguishedName!),
                       TestSettings.BindDn,
                       TestSettings.BindPassword,
                       AuthenticationTypes.SecureSocketsLayer))
            {
                Assert.DoesNotContain(
                    userDn,
                    entry.Properties["member"].Cast<object>().Select(value => value.ToString()),
                    StringComparer.OrdinalIgnoreCase);
            }

            Assert.True(domainUsers.Members.Contains(found));
            var enumeratedMemberDns = new List<string?>();
            foreach (var member in domainUsers.Members)
            {
                using (member)
                {
                    enumeratedMemberDns.Add(member.DistinguishedName);
                }
            }

            Assert.Equal(domainUsers.Members.Count, enumeratedMemberDns.Count);
            Assert.Contains(userDn, enumeratedMemberDns, StringComparer.OrdinalIgnoreCase);

            using var directMembers = domainUsers.GetMembers(recursive: false);
            Assert.Contains(
                userDn,
                directMembers.Select(member => member.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);

            using var recursiveMembers = domainUsers.GetMembers(recursive: true);
            Assert.Contains(
                userDn,
                recursiveMembers.Select(member => member.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);

            using var authorizationGroups = found.GetAuthorizationGroups();
            Assert.Contains(
                domainUsers.DistinguishedName,
                authorizationGroups.Select(group => group.DistinguishedName),
                StringComparer.OrdinalIgnoreCase);

            Assert.Throws<InvalidOperationException>(() => domainUsers.Members.Remove(found));
            Assert.Throws<InvalidOperationException>(() => domainUsers.Members.Clear());
        }
        finally
        {
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Extension_changes_are_cached_until_save_and_deleted_principals_are_rejected()
    {
        var userName = NewName();
        var userDn = DnFor(userName, TestDirectory.UsersContainer);

        try
        {
            using var context = Context();
            using var user = new ExtendedUserPrincipal(context)
            {
                Name = userName,
                SamAccountName = userName,
            };
            user.Save();

            var entry = Assert.IsType<DirectoryEntry>(user.GetUnderlyingObject());
            Assert.Null(entry.Properties["telephoneNumber"].Value);

            user.WriteExtension("telephoneNumber", "staged");
            Assert.Null(entry.Properties["telephoneNumber"].Value);
            Assert.Equal(new object[] { "staged" }, user.ReadExtension("telephoneNumber"));

            user.Save();
            Assert.Equal("staged", entry.Properties["telephoneNumber"].Value);

            user.Delete();
            Assert.Throws<InvalidOperationException>(() => user.Save());
            Assert.Throws<InvalidOperationException>(() => user.GetGroups());
            Assert.Throws<InvalidOperationException>(() => user.GetUnderlyingObject());
        }
        finally
        {
            TestDirectory.Delete(userDn);
        }
    }

    [Fact]
    public void Save_with_context_creates_and_moves_principals_to_the_target_container()
    {
        var sourceName = NewName();
        var newName = NewName();
        var targetOuName = NewName();
        var targetOuDn = CreateOrganizationalUnit(targetOuName);
        var sourceDn = DnFor(sourceName, TestDirectory.UsersContainer);
        var movedDn = DnFor(sourceName, targetOuDn);
        var newDn = DnFor(newName, targetOuDn);

        try
        {
            using var sourceContext = Context();
            using var targetContext = Context(targetOuDn);
            using (var group = new GroupPrincipal(sourceContext, sourceName))
            {
                group.Save();
                group.Save(targetContext);
                Assert.Same(targetContext, group.Context);
                Assert.Equal(movedDn, group.DistinguishedName);
            }

            using (var group = new GroupPrincipal(sourceContext, newName))
            {
                group.Save(targetContext);
                Assert.Same(targetContext, group.Context);
                Assert.Equal(newDn, group.DistinguishedName);
            }

            Assert.Null(GroupPrincipal.FindByIdentity(sourceContext, sourceName));
            using var moved = GroupPrincipal.FindByIdentity(targetContext, sourceName);
            using var created = GroupPrincipal.FindByIdentity(targetContext, newName);
            Assert.NotNull(moved);
            Assert.NotNull(created);
        }
        finally
        {
            TestDirectory.Delete(sourceDn);
            TestDirectory.Delete(movedDn);
            TestDirectory.Delete(newDn);
            TestDirectory.Delete(targetOuDn);
        }
    }
}
