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
}
