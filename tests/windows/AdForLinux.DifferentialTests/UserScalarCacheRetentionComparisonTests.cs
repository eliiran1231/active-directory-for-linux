using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class UserScalarCacheRetentionComparisonTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (var property in new[]
        {
            "GivenName", "Surname", "EmailAddress", "Description",
            "VoiceTelephoneNumber", "MiddleName", "EmployeeId",
        })
        foreach (var transition in new[] { "replace", "clear", "initially-absent", "unchanged" })
            yield return new object[] { property, transition };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Loaded_scalar_retains_its_value_after_raw_cache_edits(string property, string transition)
    {
        // Extend coverage beyond the already-fixed DisplayName cache to User
        // fields and another Principal field. Use only public cache operations;
        // the shared fixture creates and cleans up independent disabled users.
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            var attribute = property switch
            {
                "GivenName" => "givenName",
                "Surname" => "sn",
                "EmailAddress" => "mail",
                "Description" => "description",
                "VoiceTelephoneNumber" => "telephoneNumber",
                "MiddleName" => "middleName",
                "EmployeeId" => "employeeID",
                _ => throw new ArgumentOutOfRangeException(nameof(property)),
            };
            // Keep values within employeeID's 16-character schema limit too.
            string? initial = transition == "initially-absent" ? null : "initial-value";
            string? replacement = transition switch
            {
                "clear" => null,
                "unchanged" => initial,
                _ => "replacement",
            };
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            expectedEntry.Properties[attribute].Value = initial;
            actualEntry.Properties[attribute].Value = initial;
            Assert.Equal(SuiteCapture.Expected(initial, "assert-equal-expected", 54), SuiteCapture.Expected(expectedEntry.Properties[attribute].Value, "assert-equal-actual", 54));
            Assert.Equal(SuiteCapture.Expected(initial, "assert-equal-expected", 55), SuiteCapture.Expected(actualEntry.Properties[attribute].Value, "assert-equal-actual", 55));

            var expectedFirst = Read(expected, property);
            var actualFirst = Read(actual, property);
            Assert.Equal(SuiteCapture.Expected(initial, "assert-equal-expected", 59), SuiteCapture.Expected(expectedFirst, "assert-equal-actual", 59));
            var comparison = new Comparison($"{property}: {transition}")
                .Check("first projection", expectedFirst, actualFirst);

            if (transition != "unchanged")
            {
                expectedEntry.Properties[attribute].Value = replacement;
                actualEntry.Properties[attribute].Value = replacement;
            }
            // Prove that both raw caches changed before comparing the separate
            // principal cache. No Save or Commit follows these assignments.
            Assert.Equal(SuiteCapture.Expected(replacement, "assert-equal-expected", 70), SuiteCapture.Expected(expectedEntry.Properties[attribute].Value, "assert-equal-actual", 70));
            Assert.Equal(SuiteCapture.Expected(replacement, "assert-equal-expected", 71), SuiteCapture.Expected(actualEntry.Properties[attribute].Value, "assert-equal-actual", 71));
            comparison.Check("second projection", Read(expected, property), Read(actual, property));
            comparison.Check("repeated projection", Read(expected, property), Read(actual, property));
            comparison.Assert();
        });
    }

    private static string? Read(Ms.UserPrincipal user, string property) => property switch
    {
        "GivenName" => user.GivenName,
        "Surname" => user.Surname,
        "EmailAddress" => user.EmailAddress,
        "Description" => user.Description,
        "VoiceTelephoneNumber" => user.VoiceTelephoneNumber,
        "MiddleName" => user.MiddleName,
        "EmployeeId" => user.EmployeeId,
        _ => throw new ArgumentOutOfRangeException(nameof(property)),
    };

    private static string? Read(Ours.UserPrincipal user, string property) => property switch
    {
        "GivenName" => user.GivenName,
        "Surname" => user.Surname,
        "EmailAddress" => user.EmailAddress,
        "Description" => user.Description,
        "VoiceTelephoneNumber" => user.VoiceTelephoneNumber,
        "MiddleName" => user.MiddleName,
        "EmployeeId" => user.EmployeeId,
        _ => throw new ArgumentOutOfRangeException(nameof(property)),
    };
}
