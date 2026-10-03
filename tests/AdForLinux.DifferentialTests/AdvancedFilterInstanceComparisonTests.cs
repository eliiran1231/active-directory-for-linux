using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class AdvancedFilterInstanceComparisonTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var method in Methods)
        foreach (var nullOwner in new[] { true, false })
            yield return new object[] { method, nullOwner };
    }

    internal static readonly string[] Methods =
    [
        "LastBadPasswordAttempt", "AccountExpirationDate", "AccountLockoutTime",
        "BadLogonCount", "LastLogonTime", "LastPasswordSetTime",
    ];

    [Theory]
    [MemberData(nameof(Cases))]
    public void Built_in_criteria_can_be_configured_without_an_owner(string method, bool nullOwner)
    {
        using var expectedOwner = new MicrosoftPrincipal();
        using var actualOwner = new OurPrincipal();
        var expected = new MicrosoftFilters(nullOwner ? null : expectedOwner);
        var actual = new OurFilters(nullOwner ? null : actualOwner);
        var comparison = new Comparison($"{method}; null owner={nullOwner}");

        // Unlike AdvancedFilterSet, the six built-in methods store criteria on
        // the AdvancedFilters instance in Microsoft. No context is needed.
        // Exercise both creation and replacement of the stored criterion.
        foreach (var value in new[] { 3, 7 })
        {
            var expectedError = Record.Exception(() => Configure(expected, method, value));
            var actualError = Record.Exception(() => Configure(actual, method, value));
            Assert.Null(expectedError);
            CompareError(comparison, $"criterion {value}", expectedError, actualError);
        }
        comparison.Assert();
    }

    internal static void Configure(Ms.AdvancedFilters filters, string method, int value)
    {
        var date = new DateTime(2030, 1, value, 0, 0, 0, DateTimeKind.Utc);
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(date, Ms.MatchType.Equals); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(date, Ms.MatchType.Equals); break;
            case "AccountLockoutTime": filters.AccountLockoutTime(date, Ms.MatchType.Equals); break;
            case "BadLogonCount": filters.BadLogonCount(value, Ms.MatchType.Equals); break;
            case "LastLogonTime": filters.LastLogonTime(date, Ms.MatchType.Equals); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(date, Ms.MatchType.Equals); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    internal static void Configure(Ours.AdvancedFilters filters, string method, int value)
    {
        var date = new DateTime(2030, 1, value, 0, 0, 0, DateTimeKind.Utc);
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(date, Ours.MatchType.Equals); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(date, Ours.MatchType.Equals); break;
            case "AccountLockoutTime": filters.AccountLockoutTime(date, Ours.MatchType.Equals); break;
            case "BadLogonCount": filters.BadLogonCount(value, Ours.MatchType.Equals); break;
            case "LastLogonTime": filters.LastLogonTime(date, Ours.MatchType.Equals); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(date, Ours.MatchType.Equals); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    private static void CompareError(Comparison comparison, string label, Exception? expected, Exception? actual) =>
        comparison.Check($"{label}: exception", expected?.GetType().FullName, actual?.GetType().FullName)
            .Check($"{label}: parameter", (expected as ArgumentException)?.ParamName,
                (actual as ArgumentException)?.ParamName);

    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }

    // Ordinary protected constructors, not reflection or fabricated state.
    internal sealed class MicrosoftFilters(Ms.Principal? owner) : Ms.AdvancedFilters(owner!);
    internal sealed class OurFilters(Ours.Principal? owner) : Ours.AdvancedFilters(owner!);
}

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class AdvancedFilterIsolationComparisonTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var method in AdvancedFilterInstanceComparisonTests.Methods)
        foreach (var seedOwnedFilter in new[] { false, true })
            yield return new object[] { method, seedOwnedFilter };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Separate_filter_instance_does_not_change_the_principals_query(string method, bool seedOwnedFilter)
    {
        // Rendering GetUnderlyingSearcher can bind, but these cases never
        // execute a search or write an object to AD.
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expected = new Ms.UserPrincipal(expectedContext);
        using var actual = new Ours.UserPrincipal(actualContext);
        using var expectedSearcher = new Ms.PrincipalSearcher(expected);
        using var actualSearcher = new Ours.PrincipalSearcher(actual);
        var expectedDetached = new AdvancedFilterInstanceComparisonTests.MicrosoftFilters(expected);
        var actualDetached = new AdvancedFilterInstanceComparisonTests.OurFilters(actual);
        Assert.NotSame(expected.AdvancedSearchFilter, expectedDetached);
        Assert.NotSame(actual.AdvancedSearchFilter, actualDetached);

        var expectedUnfiltered = ExpectedFilter();
        var actualUnfiltered = ActualFilter();
        Assert.False(string.IsNullOrEmpty(expectedUnfiltered));
        if (seedOwnedFilter)
        {
            AdvancedFilterInstanceComparisonTests.Configure(expected.AdvancedSearchFilter, method, 3);
            AdvancedFilterInstanceComparisonTests.Configure(actual.AdvancedSearchFilter, method, 3);
        }
        var expectedBaseline = ExpectedFilter();
        var actualBaseline = ActualFilter();
        var comparison = new Comparison($"{method}; existing owned criterion={seedOwnedFilter}")
            .Check("unfiltered control", expectedUnfiltered, actualUnfiltered)
            .Check("baseline control", expectedBaseline, actualBaseline);
        if (seedOwnedFilter) Assert.NotEqual(expectedUnfiltered, expectedBaseline);

        foreach (var value in new[] { 7, 9 })
        {
            AdvancedFilterInstanceComparisonTests.Configure(expectedDetached, method, value);
            AdvancedFilterInstanceComparisonTests.Configure(actualDetached, method, value);
            var expectedFilter = ExpectedFilter();
            var actualFilter = ActualFilter();
            Assert.Equal(expectedBaseline, expectedFilter);
            comparison.Check($"after detached criterion {value}", expectedFilter, actualFilter);
        }

        // Positive control: updating the actual AdvancedSearchFilter must
        // change the rendered query and restore equivalent provider state.
        AdvancedFilterInstanceComparisonTests.Configure(expected.AdvancedSearchFilter, method, 11);
        AdvancedFilterInstanceComparisonTests.Configure(actual.AdvancedSearchFilter, method, 11);
        var expectedRecovery = ExpectedFilter();
        Assert.NotEqual(expectedBaseline, expectedRecovery);
        comparison.Check("owned filter recovery", expectedRecovery, ActualFilter()).Assert();

        string? ExpectedFilter() => Assert.IsType<System.DirectoryServices.DirectorySearcher>(
            expectedSearcher.GetUnderlyingSearcher()).Filter;
        string ActualFilter() => Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(
            actualSearcher.GetUnderlyingSearcher()).Filter;
    }
}
