using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Normal protected constructors let us test filter configuration without a
// PrincipalContext, reflection, directory discovery, or a running AD server.
public sealed class AdvancedFilterDeferralComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }
    private sealed class MicrosoftFilters(Ms.Principal principal) : Ms.AdvancedFilters(principal) { }
    private sealed class OurFilters(Ours.Principal principal) : Ours.AdvancedFilters(principal) { }

    public static IEnumerable<object[]> MatchCases()
    {
        foreach (var method in Methods)
        foreach (var match in new[] { -1, 6, 0 }) // Equals is the passing control.
            yield return new object[] { method, match };
    }

    public static IEnumerable<object[]> DateCases()
    {
        foreach (var method in Methods.Where(method => method != "BadLogonCount"))
        foreach (var year in new[] { 1, 1600, 1601 }) // FILETIME starts at 1601.
            yield return new object[] { method, year };
    }

    private static readonly string[] Methods =
    {
        "LastBadPasswordAttempt", "AccountExpirationDate", "AccountLockoutTime",
        "BadLogonCount", "LastLogonTime", "LastPasswordSetTime",
    };

    [Theory]
    [MemberData(nameof(MatchCases))]
    public void Configuring_match_type_defers_validation_like_microsoft(string method, int match)
    {
        CompareConfiguration(method, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), match);
    }

    [Theory]
    [MemberData(nameof(DateCases))]
    public void Configuring_date_defers_filetime_conversion_like_microsoft(string method, int year)
    {
        CompareConfiguration(method, new DateTime(year, 1, 1, 0, 0, 0, DateTimeKind.Utc), 0);
    }

    private static void CompareConfiguration(string method, DateTime date, int match)
    {
        using var microsoftPrincipal = new MicrosoftPrincipal();
        using var ourPrincipal = new OurPrincipal();
        var microsoft = new MicrosoftFilters(microsoftPrincipal);
        var ours = new OurFilters(ourPrincipal);

        // Setters store query criteria in Microsoft; configuring a criterion
        // is distinct from executing it. Do not assert that AD accepts it.
        var expected = Record.Exception(() => Configure(microsoft, method, date, (Ms.MatchType)match));
        var actual = Record.Exception(() => Configure(ours, method, date, (Ours.MatchType)match));

        // Also exercise replacement of an existing criterion after the attempt.
        var recoveryDate = new DateTime(2024, 2, 1, 0, 0, 0, DateTimeKind.Utc);
        var expectedRecovery = Record.Exception(() => Configure(microsoft, method, recoveryDate, Ms.MatchType.Equals));
        var actualRecovery = Record.Exception(() => Configure(ours, method, recoveryDate, Ours.MatchType.Equals));
        Assert.Equal(
            new[] { Describe(expected), Describe(expectedRecovery) },
            new[] { Describe(actual), Describe(actualRecovery) });
    }

    private static void Configure(Ms.AdvancedFilters filters, string method, DateTime date, Ms.MatchType match)
    {
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(date, match); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(date, match); break;
            case "AccountLockoutTime": filters.AccountLockoutTime(date, match); break;
            case "BadLogonCount": filters.BadLogonCount(3, match); break;
            case "LastLogonTime": filters.LastLogonTime(date, match); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(date, match); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    private static void Configure(Ours.AdvancedFilters filters, string method, DateTime date, Ours.MatchType match)
    {
        switch (method)
        {
            case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(date, match); break;
            case "AccountExpirationDate": filters.AccountExpirationDate(date, match); break;
            case "AccountLockoutTime": filters.AccountLockoutTime(date, match); break;
            case "BadLogonCount": filters.BadLogonCount(3, match); break;
            case "LastLogonTime": filters.LastLogonTime(date, match); break;
            case "LastPasswordSetTime": filters.LastPasswordSetTime(date, match); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    private static string Describe(Exception? error) => error is null
        ? "accepted"
        : $"{error.GetType().FullName}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";
}
