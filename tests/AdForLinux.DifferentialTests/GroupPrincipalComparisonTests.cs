using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Compares group reading and membership between the real Microsoft library and
/// our clone.
/// </summary>
[Collection("differential")]
public class GroupPrincipalComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public GroupPrincipalComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    private static Ms.PrincipalContext MicrosoftContext(string? container = null) =>
        new(Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            container ?? DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string? container = null) =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            container ?? DifferentialSettings.UsersContainer,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    [Fact]
    public void Group_properties_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        var ms = Ms.GroupPrincipal.FindByIdentity(msContext, _data.GroupName);
        var ours = Ours.GroupPrincipal.FindByIdentity(ourContext, _data.GroupName);

        Assert.NotNull(ms);
        Assert.NotNull(ours);

        new Comparison($"group {_data.GroupName}")
            .Check(nameof(ms.SamAccountName), ms!.SamAccountName, ours!.SamAccountName)
            .Check(nameof(ms.Name), ms.Name, ours.Name)
            .Check(nameof(ms.DistinguishedName), ms.DistinguishedName, ours.DistinguishedName)
            .Check(nameof(ms.Description), ms.Description, ours.Description)
            .Check(nameof(ms.Guid), ms.Guid, ours.Guid)
            .Check(nameof(ms.GroupScope), ms.GroupScope?.ToString(), ours.GroupScope?.ToString())
            .Check(nameof(ms.IsSecurityGroup), ms.IsSecurityGroup, ours.IsSecurityGroup)
            .Check(nameof(ms.StructuralObjectClass), ms.StructuralObjectClass, ours.StructuralObjectClass)
            .Assert();

        ms.Dispose();
        ours.Dispose();
    }

    [Fact]
    public void Members_match()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var ms = Ms.GroupPrincipal.FindByIdentity(msContext, _data.GroupName);
        using var ours = Ours.GroupPrincipal.FindByIdentity(ourContext, _data.GroupName);

        Assert.NotNull(ms);
        Assert.NotNull(ours);

        new Comparison($"members of {_data.GroupName}")
            .Check("Count", ms!.Members.Count, ours!.Members.Count)
            .CheckSet("member DNs",
                ms.Members.Select(m => m.DistinguishedName),
                ours.Members.Select(m => m.DistinguishedName))
            .Assert();
    }

    [Fact]
    public void Members_contains_agrees()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msGroup = Ms.GroupPrincipal.FindByIdentity(msContext, _data.GroupName);
        using var ourGroup = Ours.GroupPrincipal.FindByIdentity(ourContext, _data.GroupName);
        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(msGroup);
        Assert.NotNull(ourGroup);

        new Comparison("Members.Contains")
            .Check("user is a member",
                msGroup!.Members.Contains(msUser),
                ourGroup!.Members.Contains(ourUser!))
            .Assert();
    }

    [Fact]
    public void GetMembers_matches_for_direct_and_recursive_searches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var ms = Ms.GroupPrincipal.FindByIdentity(msContext, _data.NestedGroupName);
        using var ours = Ours.GroupPrincipal.FindByIdentity(ourContext, _data.NestedGroupName);

        Assert.NotNull(ms);
        Assert.NotNull(ours);

        using var msDirect = ms!.GetMembers();
        using var ourDirect = ours!.GetMembers();
        using var msRecursive = ms.GetMembers(recursive: true);
        using var ourRecursive = ours.GetMembers(recursive: true);

        new Comparison($"GetMembers for {_data.NestedGroupName}")
            .CheckSet("direct member DNs",
                msDirect.Select(p => p.DistinguishedName),
                ourDirect.Select(p => p.DistinguishedName))
            .CheckSet("recursive member DNs",
                msRecursive.Select(p => p.DistinguishedName),
                ourRecursive.Select(p => p.DistinguishedName))
            .Assert();
    }

    [Fact]
    public void GetMembers_recursive_ignores_the_context_container()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var specialOuDn = $"OU=adfl-special-{suffix},{DifferentialSettings.BaseDn}";
        var normalOuDn = $"OU=adfl-normal-{suffix},{DifferentialSettings.BaseDn}";
        var outerName = $"adfl-outer-{suffix}";
        var innerName = $"adfl-inner-{suffix}";
        var userName = $"adfl-user-{suffix}";
        var outerDn = $"CN={outerName},{specialOuDn}";
        var innerDn = $"CN={innerName},{normalOuDn}";
        var userDn = $"CN={userName},{normalOuDn}";

        try
        {
            CreateOrganizationalUnit(specialOuDn);
            CreateOrganizationalUnit(normalOuDn);
            CreateUser(userDn, userName);

            using var msSpecial = MicrosoftContext(specialOuDn);
            using var msNormal = MicrosoftContext(normalOuDn);
            using var ourSpecial = OurContext(specialOuDn);
            using var msOuter = new Ms.GroupPrincipal(msSpecial, outerName);
            using var msInner = new Ms.GroupPrincipal(msNormal, innerName);
            msOuter.Save();
            msInner.Save();

            using var msUser = Ms.UserPrincipal.FindByIdentity(msNormal, userName)!;
            msInner.Members.Add(msUser);
            msInner.Save();
            msOuter.Members.Add(msInner);
            msOuter.Save();

            using var ours = Ours.GroupPrincipal.FindByIdentity(ourSpecial, outerName)!;
            using var msMembers = msOuter.GetMembers(recursive: true);
            using var ourMembers = ours.GetMembers(recursive: true);

            new Comparison("GetMembers recursive outside the context container")
                .CheckSet("member DNs",
                    msMembers.Select(member => member.DistinguishedName),
                    ourMembers.Select(member => member.DistinguishedName))
                .Assert();
        }
        finally
        {
            Delete(outerDn);
            Delete(innerDn);
            Delete(userDn);
            Delete(specialOuDn);
            Delete(normalOuDn);
        }
    }

    [Fact]
    public void GetGroups_matches_for_the_user()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        using var msGroups = msUser!.GetGroups();
        using var ourGroups = ourUser!.GetGroups();

        new Comparison($"GetGroups for {_data.UserName}")
            .CheckSet("group DNs",
                msGroups.Select(g => g.DistinguishedName),
                ourGroups.Select(g => g.DistinguishedName))
            .Assert();
    }

    [Fact]
    public void GetGroups_is_empty_for_unsaved_principals()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUser = new Ms.UserPrincipal(msContext);
        using var ourUser = new Ours.UserPrincipal(ourContext);
        using var msGroups = msUser.GetGroups();
        using var ourGroups = ourUser.GetGroups();

        Assert.Empty(msGroups);
        Assert.Empty(ourGroups);
    }

    [Fact]
    public void Primary_group_membership_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);
        using var msDomainUsers = Ms.GroupPrincipal.FindByIdentity(
            msContext, Ms.IdentityType.SamAccountName, "Domain Users");
        using var ourDomainUsers = Ours.GroupPrincipal.FindByIdentity(
            ourContext, Ours.IdentityType.SamAccountName, "Domain Users");

        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);
        Assert.NotNull(msDomainUsers);
        Assert.NotNull(ourDomainUsers);
        Assert.Equal(msUser!.IsMemberOf(msDomainUsers!), ourUser!.IsMemberOf(ourDomainUsers!));
        Assert.True(ourUser.IsMemberOf(ourDomainUsers));
    }

    [Fact]
    public void GetAuthorizationGroups_matches_for_the_user()
    {
        // The nested group is only reachable by following the group chain, so
        // this exercises LDAP_MATCHING_RULE_IN_CHAIN on both sides.
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        using var msGroups = msUser!.GetAuthorizationGroups();
        using var ourGroups = ourUser!.GetAuthorizationGroups();

        // Microsoft's GetAuthorizationGroups also returns computed groups such as
        // "Domain Users" and well-known SIDs, which a pure LDAP query cannot see.
        // So we check that every group we found is also in Microsoft's answer,
        // and that the nested group is present on both sides.
        var msDns = msGroups.Select(g => g.DistinguishedName).Where(dn => dn is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ourDns = ourGroups.Select(g => g.DistinguishedName).Where(dn => dn is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.True(ourDns.IsSubsetOf(msDns),
            "AdForLinux returned groups Microsoft did not: " +
            string.Join(", ", ourDns.Except(msDns, StringComparer.OrdinalIgnoreCase)));

        Assert.Contains(_data.GroupDn, ourDns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(_data.NestedGroupDn, ourDns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(_data.NestedGroupDn, msDns, StringComparer.OrdinalIgnoreCase);
    }

    private static void CreateOrganizationalUnit(string distinguishedName)
    {
        var separator = distinguishedName.IndexOf(',');
        var relativeName = distinguishedName[..separator];
        var parentDn = distinguishedName[(separator + 1)..];
        using var parent = Open(parentDn);
        using var organizationalUnit = parent.Children.Add(relativeName, "organizationalUnit");
        organizationalUnit.CommitChanges();
    }

    private static void CreateUser(string distinguishedName, string samAccountName)
    {
        var separator = distinguishedName.IndexOf(',');
        var relativeName = distinguishedName[..separator];
        var parentDn = distinguishedName[(separator + 1)..];
        using var parent = Open(parentDn);
        using var user = parent.Children.Add(relativeName, "user");
        user.Properties["sAMAccountName"].Value = samAccountName;
        user.CommitChanges();
    }

    private static System.DirectoryServices.DirectoryEntry Open(string distinguishedName) =>
        new(DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            System.DirectoryServices.AuthenticationTypes.SecureSocketsLayer);

    private static void Delete(string distinguishedName)
    {
        try
        {
            using var entry = Open(distinguishedName);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup for a failed differential setup.
        }
    }
}
