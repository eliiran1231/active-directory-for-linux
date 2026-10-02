using Xunit;

namespace AdForLinux.DifferentialTests;

// Creates disposable disabled users. Refresh reads their server values, but no
// Save/Commit follows staging. Run only in the verified isolated disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityPrincipalRefreshCacheComparisonTests
{
    // Pinned dotnet/runtime v9.0.0: Principal.HandleGet retains a Loaded field;
    // DirectoryEntry.RefreshCache invalidates all or selected raw wrappers only.
    // The clone's DisplayName getter instead reads the underlying entry each time.
    // These cases extend cache-mutation coverage with an explicit server refresh,
    // using an unrelated attribute refresh as the non-invalidation control.
    [Theory]
    [InlineData("all")]
    [InlineData("displayName")]
    [InlineData("description")]
    public void Loaded_display_name_after_underlying_refresh_matches_microsoft(string refresh)
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            // Capture each account's actual baseline without loading the high-level
            // property. Do not assume a server default or equal account baselines.
            var expectedBaseline = expectedEntry.Properties["displayName"].Value;
            var actualBaseline = actualEntry.Properties["displayName"].Value;
            var staged = $"uncommitted-display-{Guid.NewGuid():N}";
            Assert.NotEqual<object>(staged, expectedBaseline);
            Assert.NotEqual<object>(staged, actualBaseline);
            expectedEntry.Properties["displayName"].Value = staged;
            actualEntry.Properties["displayName"].Value = staged;
            Assert.Equal(staged, expectedEntry.Properties["displayName"].Value);
            Assert.Equal(staged, actualEntry.Properties["displayName"].Value);

            var expectedFirst = expected.DisplayName;
            var actualFirst = actual.DisplayName;
            // Require a positive oracle projection before observing retention;
            // matching null/default values must not count as a lifecycle pass.
            Assert.Equal(staged, expectedFirst);
            var comparison = new Comparison($"Loaded DisplayName after RefreshCache({refresh})");
            comparison.Check("first projection", expectedFirst, actualFirst);

            if (refresh == "all")
            {
                expectedEntry.RefreshCache();
                actualEntry.RefreshCache();
            }
            else
            {
                expectedEntry.RefreshCache(new[] { refresh });
                actualEntry.RefreshCache(new[] { refresh });
            }

            // Establish that refresh exercised the intended raw-cache transition
            // before comparing the independent Principal cache. Read new wrappers.
            var expectedRaw = expectedEntry.Properties["displayName"].Value;
            var actualRaw = actualEntry.Properties["displayName"].Value;
            Assert.Equal(refresh == "description" ? staged : expectedBaseline, expectedRaw);
            Assert.Equal(refresh == "description" ? staged : actualBaseline, actualRaw);
            comparison.Check("projection after refresh", expected.DisplayName, actual.DisplayName);
            comparison.Assert();
        });
    }
}
