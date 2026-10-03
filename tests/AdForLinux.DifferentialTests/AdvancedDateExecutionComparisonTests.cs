using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Execute both providers against the same disposable-OU fixtures, including
// zero/unset dates and real password/logon timestamps seeded by Microsoft.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class AdvancedDateExecutionComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var method in new[] { "LastBadPasswordAttempt", "LastLogonTime", "LastPasswordSetTime" })
        foreach (var match in new[] { "GreaterThan", "GreaterThanOrEquals", "LessThan", "LessThanOrEquals" })
        foreach (var year in new[] { 2000, 2100 })
            yield return new object[] { method, match, year };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Date_queries_execute_and_return_same_principals(string method, string match, int year)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var microsoft = new Ms.UserPrincipal(expectedContext);
        using var ours = new Ours.UserPrincipal(actualContext);
        using var expectedSearcher = new Ms.PrincipalSearcher(microsoft);
        using var actualSearcher = new Ours.PrincipalSearcher(ours);
        var date = new DateTime(year, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        CompatibilityAdvancedDateQueryComparisonTests.Configure(microsoft.AdvancedSearchFilter, method, date, Enum.Parse<Ms.MatchType>(match));
        CompatibilityAdvancedDateQueryComparisonTests.Configure(ours.AdvancedSearchFilter, method, date, Enum.Parse<Ours.MatchType>(match));
        var expected = new List<string>();
        using (var results = expectedSearcher.FindAll())
            foreach (var principal in results)
                using (principal) expected.Add(Assert.IsType<string>(principal.DistinguishedName));
        var actual = new List<string>();
        using (var results = actualSearcher.FindAll())
            foreach (var principal in results)
                using (principal) actual.Add(Assert.IsType<string>(principal.DistinguishedName));

        Assert.Equal(expected.OrderBy(dn => dn, StringComparer.OrdinalIgnoreCase),
            actual.OrderBy(dn => dn, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
        // Prevent matching empty results from masking a broken query path.
        if (method != "LastBadPasswordAttempt" &&
            ((year == 2000 && match.StartsWith("Greater")) || (year == 2100 && match.StartsWith("Less"))))
            Assert.Contains(data.UserDn, expected, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(data.UnsetUserDn, expected, StringComparer.OrdinalIgnoreCase);
    }
}
