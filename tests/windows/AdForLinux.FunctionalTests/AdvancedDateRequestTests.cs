using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using SearchRequest = System.DirectoryServices.Protocols.SearchRequest;
using MatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public class AdvancedDateRequestTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var method in new[] { "LastBadPasswordAttempt", "LastLogonTime", "LastPasswordSetTime" })
        foreach (var match in new[] { MatchType.GreaterThan, MatchType.GreaterThanOrEquals,
                     MatchType.LessThan, MatchType.LessThanOrEquals })
            yield return new object[] { method, match };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Date_query_builds_valid_request_without_changing_public_filter(string method, MatchType match)
    {
        using var context = new PrincipalContext(ContextType.Domain, "dc.example.test", "DC=example,DC=test");
        using var user = new UserPrincipal(context);
        var date = new DateTime(2024, 6, 15, 12, 30, 0, DateTimeKind.Utc);
        switch (method)
        {
            case "LastBadPasswordAttempt": user.AdvancedSearchFilter.LastBadPasswordAttempt(date, match); break;
            case "LastLogonTime": user.AdvancedSearchFilter.LastLogonTime(date, match); break;
            case "LastPasswordSetTime": user.AdvancedSearchFilter.LastPasswordSetTime(date, match); break;
        }
        using var principalSearcher = new PrincipalSearcher(user);
        var exposed = principalSearcher.GetLdapFilter();
        using var root = new DirectoryEntry("LDAP://dc.example.test/DC=example,DC=test");
        using var searcher = new DirectorySearcher(root, exposed);
        var buildRequest = typeof(DirectorySearcher).GetMethod(
            "BuildRequest", BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null)!;
        var request = Assert.IsType<SearchRequest>(buildRequest.Invoke(searcher, null));
        var wireFilter = Assert.IsType<string>(request.Filter);
        var attributes = method switch
        {
            "LastBadPasswordAttempt" => new[] { "badPasswordTime" },
            "LastPasswordSetTime" => new[] { "pwdLastSet" },
            _ => new[] { "lastLogon", "lastLogonTimestamp" },
        };
        foreach (var attribute in attributes)
        {
            Assert.Contains($"(!{attribute}=0)", exposed);
            Assert.Contains($"(!({attribute}=0))", wireFilter);
            Assert.DoesNotContain($"(!{attribute}=0)", wireFilter);
        }
        Assert.Equal(exposed, searcher.Filter);
    }

    [Theory]
    [InlineData(@"(description=\28!pwdLastSet=0\29)")]
    [InlineData("(!(pwdLastSet=0))")]
    public void Normalization_preserves_literal_values_and_standard_negation(string filter)
    {
        using var root = new DirectoryEntry("LDAP://dc.example.test/DC=example,DC=test");
        using var searcher = new DirectorySearcher(root, filter);
        var buildRequest = typeof(DirectorySearcher).GetMethod(
            "BuildRequest", BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null)!;
        var request = Assert.IsType<SearchRequest>(buildRequest.Invoke(searcher, null));
        Assert.Equal(filter, request.Filter);
    }
}
