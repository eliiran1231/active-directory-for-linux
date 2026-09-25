using System.ComponentModel;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using MatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public class PrincipalQueryFilterTests
{
    private const string UserCategory = "(&(objectCategory=user)(objectClass=user)";
    private const string BitRule = "1.2.840.113556.1.4.803";

    private static PrincipalContext OfflineContext() =>
        new(ContextType.Domain, "dc.example.test", "DC=example,DC=test");

    [Fact]
    public void String_query_preserves_wildcards_but_escapes_filter_syntax()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context) { DisplayName = "team*\\2a)(cn=*)\0" };
        using var searcher = new PrincipalSearcher(user);

        Assert.Equal(UserCategory + "(displayName=team*\\5c2a\\29\\28cn=*\\29\\00))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void Unset_null_and_empty_string_have_distinct_query_meanings()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);

        Assert.Equal(UserCategory + ")", searcher.GetLdapFilter());
        user.Description = null;
        Assert.Equal(UserCategory + "(!(description=*)))", searcher.GetLdapFilter());
        user.Description = string.Empty;
        Assert.Equal(UserCategory + "(description=))", searcher.GetLdapFilter());
        user.Description = "updated";
        Assert.Equal(UserCategory + "(description=updated))", searcher.GetLdapFilter());
    }

    [Fact]
    public void Account_flags_remain_independent_when_one_property_is_reassigned()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context)
        {
            Enabled = true,
            PasswordNeverExpires = true,
            PasswordNotRequired = false,
        };
        using var searcher = new PrincipalSearcher(user);

        Assert.Equal(UserCategory +
            $"(!(userAccountControl:{BitRule}:=2))" +
            $"(userAccountControl:{BitRule}:=65536)" +
            $"(!(userAccountControl:{BitRule}:=32)))", searcher.GetLdapFilter());

        user.Enabled = false;
        user.PasswordNeverExpires = false;
        Assert.Equal(UserCategory +
            $"(userAccountControl:{BitRule}:=2)" +
            $"(!(userAccountControl:{BitRule}:=65536))" +
            $"(!(userAccountControl:{BitRule}:=32)))", searcher.GetLdapFilter());
    }

    [Theory]
    [InlineData(GroupScope.Local, 4)]
    [InlineData(GroupScope.Global, 2)]
    [InlineData(GroupScope.Universal, 8)]
    public void Group_scope_and_security_bit_are_separate_query_predicates(GroupScope scope, int bit)
    {
        using var context = OfflineContext();
        using var group = new GroupPrincipal(context) { GroupScope = scope, IsSecurityGroup = true };
        using var searcher = new PrincipalSearcher(group);

        AssertGroupPredicates(searcher, $"(groupType:{BitRule}:={bit})",
            $"(groupType:{BitRule}:=2147483648)");

        group.IsSecurityGroup = false;
        AssertGroupPredicates(searcher, $"(groupType:{BitRule}:={bit})",
            $"(!(groupType:{BitRule}:=2147483648))");
    }

    private static void AssertGroupPredicates(PrincipalSearcher searcher, string scope, string security)
    {
        // LDAP conjunction order is immaterial; require exactly these two predicates.
        Assert.Contains(searcher.GetLdapFilter(), new[]
        {
            $"(&(objectClass=group){scope}{security})",
            $"(&(objectClass=group){security}{scope})",
        });
    }

    [Fact]
    public void Account_expiration_null_matches_both_never_expires_representations()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);

        Assert.Equal(UserCategory + ")", searcher.GetLdapFilter());
        user.AccountExpirationDate = DateTime.FromFileTimeUtc(123456789);
        Assert.Equal(UserCategory + "(accountExpires=123456789))", searcher.GetLdapFilter());
        user.AccountExpirationDate = null;
        Assert.Equal(UserCategory + "(|(accountExpires=9223372036854775807)(accountExpires=0)))",
            searcher.GetLdapFilter());
    }

    [Fact]
    public void Workstation_edits_replace_predicates_and_clear_removes_the_constraint()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);
        user.PermittedWorkstations.Add("DESK(01)");
        user.PermittedWorkstations.Add("LAB*");
        Assert.Equal(UserCategory + "(userWorkstations=*DESK\\2801\\29*)(userWorkstations=*LAB**))",
            searcher.GetLdapFilter());

        user.PermittedWorkstations.RemoveAt(0);
        Assert.Equal(UserCategory + "(userWorkstations=*LAB**))", searcher.GetLdapFilter());
        user.PermittedWorkstations.Clear();
        Assert.Equal(UserCategory + ")", searcher.GetLdapFilter());
    }

    [Fact]
    public void Service_principal_name_edits_are_reflected_by_an_existing_searcher()
    {
        using var context = OfflineContext();
        using var computer = new ComputerPrincipal(context);
        using var searcher = new PrincipalSearcher(computer);
        computer.ServicePrincipalNames.Add("HOST/server*");
        computer.ServicePrincipalNames.Add("HTTP/(legacy)");
        Assert.Equal("(&(objectClass=computer)(servicePrincipalName=HOST/server*)" +
            "(servicePrincipalName=HTTP/\\28legacy\\29))", searcher.GetLdapFilter());

        computer.ServicePrincipalNames[0] = "HOST/replacement";
        computer.ServicePrincipalNames.RemoveAt(1);
        Assert.Equal("(&(objectClass=computer)(servicePrincipalName=HOST/replacement))",
            searcher.GetLdapFilter());
        computer.ServicePrincipalNames.Clear();
        Assert.Equal("(&(objectClass=computer))", searcher.GetLdapFilter());
    }

    [Fact]
    public void Binary_logon_hours_are_escaped_as_octets_and_null_clears_the_query()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);
        user.PermittedLogonTimes = Enumerable.Repeat((byte)0xff, 21).ToArray();
        Assert.Equal(UserCategory + "(logonHours=" + string.Concat(Enumerable.Repeat("\\ff", 21)) + "))",
            searcher.GetLdapFilter());
        user.PermittedLogonTimes = null;
        Assert.Equal(UserCategory + ")", searcher.GetLdapFilter());
    }

    [Theory]
    [InlineData(MatchType.Equals, "(badPwdCount=3)")]
    [InlineData(MatchType.NotEquals, "(!(badPwdCount=3))")]
    [InlineData(MatchType.GreaterThan, "(&(badPwdCount>=3)(!(badPwdCount=3))(badPwdCount=*))")]
    [InlineData(MatchType.GreaterThanOrEquals, "(badPwdCount>=3)")]
    [InlineData(MatchType.LessThan, "(&(badPwdCount<=3)(!(badPwdCount=3))(badPwdCount=*))")]
    [InlineData(MatchType.LessThanOrEquals, "(badPwdCount<=3)")]
    public void Advanced_count_comparisons_preserve_equality_and_presence_semantics(MatchType match, string expected)
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);

        user.AdvancedSearchFilter.BadLogonCount(3, match);
        Assert.Equal(UserCategory + expected + ")", searcher.GetLdapFilter());
    }

    [Fact]
    public void Replacing_an_advanced_filter_keeps_other_attributes_and_invalid_edits_keep_previous_query()
    {
        using var context = OfflineContext();
        using var user = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(user);
        user.AdvancedSearchFilter.BadLogonCount(1, MatchType.Equals);
        user.AdvancedSearchFilter.LastPasswordSetTime(DateTime.FromFileTimeUtc(123456789), MatchType.Equals);
        user.AdvancedSearchFilter.BadLogonCount(3, MatchType.GreaterThanOrEquals);

        var expected = UserCategory + "(badPwdCount>=3)(pwdLastSet=123456789))";
        Assert.Equal(expected, searcher.GetLdapFilter());
        Assert.Throws<InvalidEnumArgumentException>(() =>
            user.AdvancedSearchFilter.BadLogonCount(99, (MatchType)int.MaxValue));
        Assert.Equal(expected, searcher.GetLdapFilter());
    }
}
