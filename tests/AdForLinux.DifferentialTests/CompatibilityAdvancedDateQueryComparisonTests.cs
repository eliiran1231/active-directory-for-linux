using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Read-only query translation, but contexts/native searchers can bind.
// Run only in the verified disposable lab. Never execute the rendered filter.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityAdvancedDateQueryComparisonTests
{
    [Theory]
    [InlineData("LastBadPasswordAttempt", "LessThanOrEquals")]
    [InlineData("LastBadPasswordAttempt", "GreaterThanOrEquals")]
    [InlineData("LastPasswordSetTime", "LessThanOrEquals")]
    [InlineData("LastPasswordSetTime", "GreaterThanOrEquals")]
    [InlineData("LastLogonTime", "LessThanOrEquals")]
    [InlineData("LastLogonTime", "GreaterThanOrEquals")]
    [InlineData("LastLogonTime", "NotEquals")]
    [InlineData("AccountExpirationDate", "LessThanOrEquals")]
    [InlineData("AccountExpirationDate", "GreaterThanOrEquals")]
    public void Advanced_date_filter_and_replacement_match_microsoft(string method, string match)
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
        var date = new DateTime(2024, 6, 15, 12, 30, 0, DateTimeKind.Utc);

        Configure(microsoft.AdvancedSearchFilter, method, date, Enum.Parse<Ms.MatchType>(match));
        Configure(ours.AdvancedSearchFilter, method, date, Enum.Parse<Ours.MatchType>(match));
        var expectedInitial = MicrosoftFilter(expectedSearcher);
        var actualInitial = OurFilter(actualSearcher);

        // The same public native-searcher surface must reflect replacement,
        // including removing range-only default-value exclusion clauses.
        Configure(microsoft.AdvancedSearchFilter, method, date.AddDays(1), Ms.MatchType.Equals);
        Configure(ours.AdvancedSearchFilter, method, date.AddDays(1), Ours.MatchType.Equals);
        var expectedReplacement = MicrosoftFilter(expectedSearcher);
        var actualReplacement = OurFilter(actualSearcher);
        Assert.False(string.IsNullOrEmpty(expectedInitial));
        Assert.False(string.IsNullOrEmpty(expectedReplacement));
        Assert.NotEqual(expectedInitial, expectedReplacement);
        Assert.Equal(new[] { expectedInitial, expectedReplacement }, new[] { actualInitial, actualReplacement });
    }

    // Compare the literal public Filter, not a hand-built expected LDAP string.
    // Source: dotnet/runtime v9.0.0 AD/ADStoreCtx_Query.cs,
    // DefaultValutMatchingDateTimeConverter, LastLogonConverter and DateTimeFilterBuilder.
    private static string? MicrosoftFilter(Ms.PrincipalSearcher searcher) =>
        Assert.IsType<System.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;

    private static string? OurFilter(Ours.PrincipalSearcher searcher) =>
        Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(searcher.GetUnderlyingSearcher()).Filter;

    internal static void Configure(Ms.AdvancedFilters filters, string method, DateTime value, Ms.MatchType match)
    {
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(value, match); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(value, match); break;
            case "LastLogonTime": filters.LastLogonTime(value, match); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(value, match); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    internal static void Configure(Ours.AdvancedFilters filters, string method, DateTime value, Ours.MatchType match)
    {
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(value, match); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(value, match); break;
            case "LastLogonTime": filters.LastLogonTime(value, match); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(value, match); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }
}
