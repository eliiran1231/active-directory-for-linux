using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class ForeignGroupMembershipConversionTests
{
    private static readonly byte[] Sid =
        { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
          0x15, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44 };

    [Fact]
    public void Principal_factory_classifies_foreign_security_principals()
    {
        var type = PrincipalFactory.SelectPrincipalType(
            new[] { "top", "FOREIGNSECURITYPRINCIPAL" });

        Assert.Equal(typeof(ForeignSecurityPrincipal), type);
    }

    [Fact]
    public void Same_forest_members_keep_their_distinguished_name()
    {
        const string dn = "CN=Member,OU=Accounts,DC=example,DC=com";

        var value = GroupMembershipConverter.SelectValue(
            isForeignSecurityPrincipal: false,
            sameForest: true,
            distinguishedName: dn,
            sid: Sid);

        Assert.Equal(dn, value);
    }

    [Fact]
    public void Cross_forest_members_use_the_microsoft_sid_binding_form()
    {
        var value = GroupMembershipConverter.SelectValue(
            isForeignSecurityPrincipal: false,
            sameForest: false,
            distinguishedName: "CN=Member,DC=foreign,DC=example",
            sid: Sid);

        Assert.Equal("<SID=01050000000000051500000011223344>", value);
    }

    [Fact]
    public void Store_local_foreign_security_principals_also_use_sid_form()
    {
        var value = GroupMembershipConverter.SelectValue(
            isForeignSecurityPrincipal: true,
            sameForest: true,
            distinguishedName:
                "CN=S-1-5-21-1,CN=ForeignSecurityPrincipals,DC=example,DC=com",
            sid: Sid);

        Assert.Equal("<SID=01050000000000051500000011223344>", value);
    }

    [Fact]
    public void Cross_forest_conversion_requires_a_sid()
    {
        Assert.Throws<PrincipalOperationException>(() =>
            GroupMembershipConverter.SelectValue(
                isForeignSecurityPrincipal: false,
                sameForest: false,
                distinguishedName: "CN=Member,DC=foreign,DC=example",
                sid: null));
    }

    [Fact]
    public void Forest_comparison_is_case_insensitive()
    {
        Assert.True(GroupMembershipConverter.AreSameForest(
            "DC=Example,DC=Com", "dc=example,dc=com"));
        Assert.False(GroupMembershipConverter.AreSameForest(
            "DC=example,DC=com", "DC=other,DC=com"));
    }

    [Fact]
    public void Same_forest_add_contains_and_remove_round_trip_with_dn_membership()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var userName = $"i57u-{suffix}";
        var groupName = $"i57g-{suffix}";
        using var context = TestSettings.CreatePrincipalContext(TestSettings.BaseDn);
        using var user = new UserPrincipal(context)
        {
            Name = userName,
            SamAccountName = userName,
        };
        using var group = new GroupPrincipal(context, groupName);

        try
        {
            user.Save();
            group.Save();

            group.Members.Add(user);
            group.Save();
            Assert.True(group.Members.Contains(user));
            using (var enumerated = Assert.Single(group.Members))
            {
                Assert.Equal(user.DistinguishedName, enumerated.DistinguishedName);
            }

            Assert.True(group.Members.Remove(user));
            group.Save();
            Assert.False(group.Members.Contains(user));
        }
        finally
        {
            if (group.IsPersisted)
            {
                group.Delete();
            }

            if (user.IsPersisted)
            {
                user.Delete();
            }
        }
    }
}
