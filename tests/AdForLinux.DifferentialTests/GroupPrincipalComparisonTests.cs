using System.Collections;
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
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string? container = null) =>
        new(Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            container ?? DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions,
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
    public void Members_collection_contract_matches()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var msGroup = Ms.GroupPrincipal.FindByIdentity(msContext, _data.GroupName);
        using var ourGroup = Ours.GroupPrincipal.FindByIdentity(ourContext, _data.GroupName);
        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(msGroup);
        Assert.NotNull(ourGroup);
        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        ICollection<Ms.Principal> msGeneric = msGroup!.Members;
        ICollection<Ours.Principal> ourGeneric = ourGroup!.Members;
        ICollection msNongeneric = msGroup.Members;
        ICollection ourNongeneric = ourGroup.Members;

        new Comparison("PrincipalCollection surface")
            .Check("IsReadOnly", msGeneric.IsReadOnly, ourGeneric.IsReadOnly)
            .Check("IsSynchronized", msNongeneric.IsSynchronized, ourNongeneric.IsSynchronized)
            .Check("SyncRoot is collection",
                ReferenceEquals(msGroup.Members, msNongeneric.SyncRoot),
                ReferenceEquals(ourGroup.Members, ourNongeneric.SyncRoot))
            .Check("negative CopyTo exception",
                Record.Exception(() => msNongeneric.CopyTo(Array.Empty<Ms.Principal>(), -1))?.GetType().Name,
                Record.Exception(() => ourNongeneric.CopyTo(Array.Empty<Ours.Principal>(), -1))?.GetType().Name)
            .Check("null CopyTo exception",
                Record.Exception(() => msNongeneric.CopyTo(null!, 0))?.GetType().Name,
                Record.Exception(() => ourNongeneric.CopyTo(null!, 0))?.GetType().Name)
            .Check("multidimensional CopyTo exception",
                Record.Exception(() => msNongeneric.CopyTo(new Ms.Principal[1, 1], 0))?.GetType().Name,
                Record.Exception(() => ourNongeneric.CopyTo(new Ours.Principal[1, 1], 0))?.GetType().Name)
            .Check("index at length CopyTo exception",
                Record.Exception(() => msNongeneric.CopyTo(new Ms.Principal[msGroup.Members.Count], msGroup.Members.Count))?.GetType().Name,
                Record.Exception(() => ourNongeneric.CopyTo(new Ours.Principal[ourGroup.Members.Count], ourGroup.Members.Count))?.GetType().Name)
            .Check("duplicate Add exception",
                Record.Exception(() => msGroup.Members.Add(msUser!))?.GetType().Name,
                Record.Exception(() => ourGroup.Members.Add(ourUser!))?.GetType().Name)
            .Check("missing identity Contains",
                msGroup.Members.Contains(
                    msContext, Ms.IdentityType.SamAccountName, "no-such-principal-xyz"),
                ourGroup.Members.Contains(
                    ourContext, Ours.IdentityType.SamAccountName, "no-such-principal-xyz"))
            .Assert();

        var msCopy = new Ms.Principal[msGroup.Members.Count];
        var ourCopy = new Ours.Principal[ourGroup.Members.Count];
        msGroup.Members.CopyTo(msCopy, 0);
        ourGroup.Members.CopyTo(ourCopy, 0);
        new Comparison("PrincipalCollection CopyTo")
            .CheckSet("member DNs",
                msCopy.Select(principal => principal.DistinguishedName),
                ourCopy.Select(principal => principal.DistinguishedName))
            .Assert();
        foreach (var principal in msCopy)
        {
            principal.Dispose();
        }

        foreach (var principal in ourCopy)
        {
            principal.Dispose();
        }
    }

    [Fact]
    public void Members_mutation_state_machine_matches_across_saves()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var msName = $"adfl-ms-state-{suffix}";
        var ourName = $"adfl-our-state-{suffix}";
        var msDn = $"CN={msName},{DifferentialSettings.UsersContainer}";
        var ourDn = $"CN={ourName},{DifferentialSettings.UsersContainer}";

        try
        {
            using var msContext = MicrosoftContext();
            using var ourContext = OurContext();
            using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName)!;
            using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName)!;
            using var msOther = Ms.UserPrincipal.FindByIdentity(msContext, _data.UnsetUserName)!;
            using var ourOther = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UnsetUserName)!;
            using var msGroup = new Ms.GroupPrincipal(msContext, msName);
            using var ourGroup = new Ours.GroupPrincipal(ourContext, ourName);
            msGroup.Save();
            ourGroup.Save();

            var msState = ExerciseMembershipState(msGroup, msUser, msOther);
            var ourState = ExerciseMembershipState(ourGroup, ourUser, ourOther);
            Assert.Equal(msState, ourState);

            using var msUnsaved = new Ms.GroupPrincipal(msContext, $"unsaved-{suffix}");
            using var ourUnsaved = new Ours.GroupPrincipal(ourContext, $"unsaved-{suffix}");
            msUnsaved.Members.Add(msUser);
            ourUnsaved.Members.Add(ourUser);
            new Comparison("unsaved PrincipalCollection state")
                .Check("Count after Add", msUnsaved.Members.Count, ourUnsaved.Members.Count)
                .Check("Remove", msUnsaved.Members.Remove(msUser), ourUnsaved.Members.Remove(ourUser))
                .Check("Count after Remove", msUnsaved.Members.Count, ourUnsaved.Members.Count)
                .Assert();

            var msMembers = msUnsaved.Members;
            var ourMembers = ourUnsaved.Members;
            msUnsaved.Dispose();
            ourUnsaved.Dispose();
            Assert.Equal(
                Record.Exception(() => _ = msMembers.Count)?.GetType().Name,
                Record.Exception(() => _ = ourMembers.Count)?.GetType().Name);
        }
        finally
        {
            Delete(msDn);
            Delete(ourDn);
        }
    }

    private static string[] ExerciseMembershipState<TGroup, TPrincipal>(
        TGroup group,
        TPrincipal member,
        TPrincipal nonMember)
        where TGroup : IDisposable
        where TPrincipal : IDisposable
    {
        if (group is Ms.GroupPrincipal msGroup && member is Ms.Principal msMember && nonMember is Ms.Principal msOther)
        {
            msGroup.Members.Add(msMember);
            var addRemove = msGroup.Members.Remove(msMember);
            msGroup.Save();
            msGroup.Save();
            msGroup.Members.Add(msMember);
            msGroup.Save();
            var duplicate = Record.Exception(() => msGroup.Members.Add(msMember))?.GetType().Name;
            var removeAdd = msGroup.Members.Remove(msMember);
            msGroup.Members.Add(msMember);
            msGroup.Save();
            var nonMemberResult = msGroup.Members.Remove(msOther);
            msGroup.Members.Clear();
            msGroup.Save();
            return new[]
            {
                addRemove.ToString(), duplicate ?? "", removeAdd.ToString(),
                nonMemberResult.ToString(), msGroup.Members.Count.ToString(),
            };
        }

        var ourGroup = (Ours.GroupPrincipal)(object)group;
        var ourMember = (Ours.Principal)(object)member;
        var ourOther = (Ours.Principal)(object)nonMember;
        ourGroup.Members.Add(ourMember);
        var ourAddRemove = ourGroup.Members.Remove(ourMember);
        ourGroup.Save();
        ourGroup.Save();
        ourGroup.Members.Add(ourMember);
        ourGroup.Save();
        var ourDuplicate = Record.Exception(() => ourGroup.Members.Add(ourMember))?.GetType().Name;
        var ourRemoveAdd = ourGroup.Members.Remove(ourMember);
        ourGroup.Members.Add(ourMember);
        ourGroup.Save();
        var ourNonMemberResult = ourGroup.Members.Remove(ourOther);
        ourGroup.Members.Clear();
        ourGroup.Save();
        return new[]
        {
            ourAddRemove.ToString(), ourDuplicate ?? "", ourRemoveAdd.ToString(),
            ourNonMemberResult.ToString(), ourGroup.Members.Count.ToString(),
        };
    }

    [Fact]
    public void Primary_group_mutation_guards_match()
    {
        // Built-in accounts live outside the isolated mutation OU. Search the
        // domain naming context for this read-only compatibility comparison.
        using var msContext = MicrosoftContext(DifferentialSettings.DomainDn);
        using var ourContext = OurContext(DifferentialSettings.DomainDn);
        using var msGroup = Ms.GroupPrincipal.FindByIdentity(
            msContext, Ms.IdentityType.SamAccountName, "Domain Users");
        using var ourGroup = Ours.GroupPrincipal.FindByIdentity(
            ourContext, Ours.IdentityType.SamAccountName, "Domain Users");
        using var msUser = Ms.UserPrincipal.FindByIdentity(
            msContext, Ms.IdentityType.SamAccountName, "Administrator");
        using var ourUser = Ours.UserPrincipal.FindByIdentity(
            ourContext, Ours.IdentityType.SamAccountName, "Administrator");

        Assert.NotNull(msGroup);
        Assert.NotNull(ourGroup);
        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        new Comparison("primary-group membership guards")
            .Check("Contains",
                msGroup!.Members.Contains(msUser!),
                ourGroup!.Members.Contains(ourUser!))
            .Check("Remove exception",
                Record.Exception(() => msGroup.Members.Remove(msUser))?.GetType().Name,
                Record.Exception(() => ourGroup.Members.Remove(ourUser))?.GetType().Name)
            .Check("Clear exception",
                Record.Exception(() => msGroup.Members.Clear())?.GetType().Name,
                Record.Exception(() => ourGroup.Members.Clear())?.GetType().Name)
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
    public void GetGroups_with_context_matches_for_the_user()
    {
        using var msContext = MicrosoftContext();
        using var ourContext = OurContext();

        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);

        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);

        using var msGroups = msUser!.GetGroups(msContext);
        using var ourGroups = ourUser!.GetGroups(ourContext);

        new Comparison($"GetGroups(context) for {_data.UserName}")
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
        using var msDomainContext = MicrosoftContext(DifferentialSettings.DomainDn);
        using var ourDomainContext = OurContext(DifferentialSettings.DomainDn);
        using var msUser = Ms.UserPrincipal.FindByIdentity(msContext, _data.UserName);
        using var ourUser = Ours.UserPrincipal.FindByIdentity(ourContext, _data.UserName);
        using var msDomainUsers = Ms.GroupPrincipal.FindByIdentity(
            msDomainContext, Ms.IdentityType.SamAccountName, "Domain Users");
        using var ourDomainUsers = Ours.GroupPrincipal.FindByIdentity(
            ourDomainContext, Ours.IdentityType.SamAccountName, "Domain Users");

        Assert.NotNull(msUser);
        Assert.NotNull(ourUser);
        Assert.NotNull(msDomainUsers);
        Assert.NotNull(ourDomainUsers);
        Assert.Equal(msUser!.IsMemberOf(msDomainUsers!), ourUser!.IsMemberOf(ourDomainUsers!));
        Assert.False(ourUser.IsMemberOf(ourDomainUsers));

        using (var rawGroup = Open(msDomainUsers.DistinguishedName))
        {
            Assert.DoesNotContain(
                _data.UserDn,
                rawGroup.Properties["member"].Cast<object>().Select(value => value.ToString()),
                StringComparer.OrdinalIgnoreCase);
        }

        new Comparison("primary-group-only Members")
            .Check("Count", msDomainUsers.Members.Count, ourDomainUsers.Members.Count)
            .Check("Contains", msDomainUsers.Members.Contains(msUser), ourDomainUsers.Members.Contains(ourUser))
            .CheckSet(
                "member DNs",
                msDomainUsers.Members.Select(member => member.DistinguishedName),
                ourDomainUsers.Members.Select(member => member.DistinguishedName))
            .Assert();

        using var msDirect = msDomainUsers.GetMembers(recursive: false);
        using var ourDirect = ourDomainUsers.GetMembers(recursive: false);
        using var msRecursive = msDomainUsers.GetMembers(recursive: true);
        using var ourRecursive = ourDomainUsers.GetMembers(recursive: true);
        new Comparison("primary-group-only GetMembers")
            .CheckSet(
                "direct member DNs",
                msDirect.Select(member => member.DistinguishedName),
                ourDirect.Select(member => member.DistinguishedName))
            .CheckSet(
                "recursive member DNs",
                msRecursive.Select(member => member.DistinguishedName),
                ourRecursive.Select(member => member.DistinguishedName))
            .Assert();

        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => msDomainUsers.Members.Remove(msUser)));
        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => ourDomainUsers.Members.Remove(ourUser)));
        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => msDomainUsers.Members.Clear()));
        Assert.IsType<InvalidOperationException>(
            Record.Exception(() => ourDomainUsers.Members.Clear()));
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
        Assert.Contains(
            ourGroups.Single(group => group.SamAccountName == "Domain Users").DistinguishedName,
            msDns,
            StringComparer.OrdinalIgnoreCase);
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
            DifferentialSettings.MicrosoftAuthenticationTypes);

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
