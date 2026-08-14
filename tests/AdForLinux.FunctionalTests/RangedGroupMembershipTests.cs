using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class RangedGroupMembershipTests
{
    private const int MemberCount = 1601;

    private static DirectoryEntry Open(string dn) =>
        new(
            TestSettings.PathFor(dn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    [Theory]
    [InlineData("member;range=0-1499", 0, 1499)]
    [InlineData("MEMBER;RANGE=1500-*", 1500, null)]
    public void Ranged_attribute_names_are_parsed_case_insensitively(
        string returnedName,
        int expectedStart,
        int? expectedEnd)
    {
        Assert.True(RangedAttributeReader.TryParseReturnedName(
            returnedName,
            "member",
            out var start,
            out var end));
        Assert.Equal(expectedStart, start);
        Assert.Equal(expectedEnd, end);
    }

    [Theory]
    [InlineData("member")]
    [InlineData("member;range=0-")]
    [InlineData("member;range=2-1")]
    [InlineData("memberOf;range=0-*")]
    public void Invalid_or_different_ranged_attribute_names_are_rejected(string returnedName)
    {
        Assert.False(RangedAttributeReader.TryParseReturnedName(
            returnedName,
            "member",
            out _,
            out _));
    }

    [Fact]
    public void Large_group_membership_reads_every_returned_range()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var organizationalUnitName = $"adfl-range-{suffix}";
        var organizationalUnitDn = $"OU={organizationalUnitName},{TestSettings.BaseDn}";
        var groupName = $"adfl-range-group-{suffix}";
        var groupDn = $"CN={groupName},{organizationalUnitDn}";
        var memberDns = Enumerable.Range(0, MemberCount)
            .Select(index => $"CN=adfl-range-{suffix}-{index:D4},{organizationalUnitDn}")
            .ToArray();

        try
        {
            using (var domain = Open(TestSettings.BaseDn))
            using (var organizationalUnit = domain.Children.Add(
                       $"OU={organizationalUnitName}",
                       "organizationalUnit"))
            {
                organizationalUnit.CommitChanges();
            }

            using var container = Open(organizationalUnitDn);
            var connection = container.GetConnection();
            connection.SendRequest(new AddRequest(
                groupDn,
                new DirectoryAttribute("objectClass", "top", "group"),
                new DirectoryAttribute("sAMAccountName", groupName),
                new DirectoryAttribute("groupType", "-2147483646")));

            for (var index = 0; index < memberDns.Length; index++)
            {
                var name = $"adfl-range-{suffix}-{index:D4}";
                connection.SendRequest(new AddRequest(
                    memberDns[index],
                    new DirectoryAttribute(
                        "objectClass",
                        "top",
                        "person",
                        "organizationalPerson",
                        "user"),
                    new DirectoryAttribute("sAMAccountName", name)));
            }

            var addMembers = new DirectoryAttributeModification
            {
                Name = "member",
                Operation = DirectoryAttributeOperation.Add,
            };
            foreach (var memberDn in memberDns)
            {
                addMembers.Add(memberDn);
            }

            var addMembersRequest = new ModifyRequest(groupDn);
            addMembersRequest.Modifications.Add(addMembers);
            connection.SendRequest(addMembersRequest);

            var raw = (SearchResponse)connection.SendRequest(new SearchRequest(
                groupDn,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Base,
                "member"));
            Assert.Equal(MemberCount, raw.Entries[0].Attributes["member"].Count);

            using var context = TestSettings.CreatePrincipalContext(organizationalUnitDn);
            using var group = GroupPrincipal.FindByIdentity(context, groupName);
            Assert.NotNull(group);
            // This exercises PrincipalCollection's production membership path.
            // Samba returns the entire attribute under its plain name while AD
            // returns member;range=...; RangedAttributeReader supports both.
            Assert.Equal(MemberCount, group!.Members.Count);

            foreach (var index in new[] { 0, MemberCount / 2, MemberCount - 1 })
            {
                using var member = UserPrincipal.FindByIdentity(
                    context,
                    $"adfl-range-{suffix}-{index:D4}");
                Assert.NotNull(member);
                Assert.True(group.Members.Contains(member!));
            }

            using (var directMembers = group.GetMembers())
            {
                var directDns = directMembers
                    .Select(member => member.DistinguishedName)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                Assert.Equal(MemberCount, directDns.Count);
                Assert.Contains(memberDns[0], directDns);
                Assert.Contains(memberDns[MemberCount / 2], directDns);
                Assert.Contains(memberDns[^1], directDns);
            }

            using (var last = UserPrincipal.FindByIdentity(
                       context,
                       $"adfl-range-{suffix}-{MemberCount - 1:D4}"))
            {
                Assert.NotNull(last);
                group.Members.Remove(last!);
                group.Save();
                Assert.False(group.Members.Contains(last!));
                Assert.Equal(MemberCount - 1, group.Members.Count);

                group.Members.Add(last!);
                group.Save();
                Assert.True(group.Members.Contains(last!));
                Assert.Equal(MemberCount, group.Members.Count);
            }

            group.Members.Clear();
            group.Save();
            Assert.Empty(group.Members);
        }
        finally
        {
            TestDirectory.Delete(organizationalUnitDn);
        }
    }
}
