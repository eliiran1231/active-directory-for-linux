using System.Globalization;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Creates disposable accounts, then mutates only their public property caches.
// Never Save/Commit/Refresh after staging; use only the verified isolated lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityCachedScalarLifecycleComparisonTests
{
    // Three independent cache families, not a property-wide matrix:
    // Principal.HandleGet<string>, AccountInfo.HandleGet<int>, and
    // PasswordInfo.HandleGet<DateTime?> retain their loaded values in Microsoft.
    // Pinned reference: dotnet/runtime v9.0.0 AccountManagement/{Principal,
    // AccountInfo,PasswordInfo}.cs. The clone reads DirectoryEntry on each call.
    [Theory]
    [InlineData("DisplayName", false)]
    [InlineData("DisplayName", true)]
    [InlineData("BadLogonCount", false)]
    [InlineData("BadLogonCount", true)]
    [InlineData("LastPasswordSet", false)]
    [InlineData("LastPasswordSet", true)]
    public void Loaded_scalar_reread_matches_microsoft_after_underlying_cache_change(string property, bool change)
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            var attribute = property switch
            {
                "DisplayName" => "displayName",
                "BadLogonCount" => "badPwdCount",
                _ => "pwdLastSet",
            };
            var initialDate = new DateTime(2030, 3, 4, 5, 6, 7, DateTimeKind.Utc);
            object initial = property switch
            {
                "DisplayName" => "initial-display",
                "BadLogonCount" => 7,
                _ => initialDate.ToFileTimeUtc(),
            };
            object replacement = property switch
            {
                "DisplayName" => "replacement-display",
                "BadLogonCount" => 11,
                _ => initialDate.AddDays(9).ToFileTimeUtc(),
            };
            StageMicrosoft(initial);
            actualEntry.Properties[attribute].Value = initial;
            VerifyRaw(initial);
            var expectedFirst = Read(expected, property);
            var actualFirst = Read(actual, property);
            // A provider cache that did not reach the principal must fail setup,
            // rather than turn matching nulls/defaults into a lifecycle pass.
            Assert.Equal(Describe(property == "LastPasswordSet" ? initialDate : initial), Describe(expectedFirst));
            var comparison = new Comparison($"Loaded {property}; underlying cache changed={change}");
            comparison.Check("first projection", Describe(expectedFirst), Describe(actualFirst));
            if (change)
            {
                StageMicrosoft(replacement);
                actualEntry.Properties[attribute].Value = replacement;
            }
            VerifyRaw(change ? replacement : initial);
            // Compare actual oracle behavior; do not encode whether rereading
            // should return the initially loaded or the newly staged value.
            comparison.Check("second projection", Describe(Read(expected, property)), Describe(Read(actual, property)));
            comparison.Assert();

            void StageMicrosoft(object value)
            {
                if (property == "LastPasswordSet")
                    CompatibilityCachedLogonProjectionComparisonTests.StageMicrosoftFileTime(expectedEntry, attribute, (long)value);
                else
                    expectedEntry.Properties[attribute].Value = value;
            }

            void VerifyRaw(object value)
            {
                if (property == "LastPasswordSet")
                {
                    Assert.Equal((long)value,
                        CompatibilityCachedLogonProjectionComparisonTests.CachedFileTime(expectedEntry.Properties[attribute].Value));
                    Assert.Equal(value, actualEntry.Properties[attribute].Value);
                }
                else
                {
                    Assert.Equal(value, expectedEntry.Properties[attribute].Value);
                    Assert.Equal(value, actualEntry.Properties[attribute].Value);
                }
            }
        });
    }

    private static object? Read(Ms.UserPrincipal principal, string property) => property switch
    {
        "DisplayName" => principal.DisplayName,
        "BadLogonCount" => principal.BadLogonCount,
        _ => principal.LastPasswordSet,
    };

    private static object? Read(Ours.UserPrincipal principal, string property) => property switch
    {
        "DisplayName" => principal.DisplayName,
        "BadLogonCount" => principal.BadLogonCount,
        _ => principal.LastPasswordSet,
    };

    private static string Describe(object? value) => value switch
    {
        null => "null",
        DateTime date => $"date:ticks={date.Ticks};kind={date.Kind}",
        string text => $"string:{text}",
        int count => $"integer:{count.ToString(CultureInfo.InvariantCulture)}",
        _ => throw new InvalidOperationException($"Unexpected projected type {value.GetType().Name}."),
    };
}
