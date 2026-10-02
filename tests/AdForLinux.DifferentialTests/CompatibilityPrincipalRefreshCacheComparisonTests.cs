using Xunit;
using MsDirectory = System.DirectoryServices;

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
            // Persist a nonempty raw baseline without loading either Principal's
            // DisplayName. ADSI GetInfoEx can retain a staged value when the server
            // omits an absent attribute, so an absent baseline cannot establish
            // targeted-refresh invalidation. Commit only this setup value, never
            // the later staged value whose cache lifetime is under comparison.
            var baseline = $"persisted-display-{Guid.NewGuid():N}";
            expectedEntry.Properties["displayName"].Value = baseline;
            actualEntry.Properties["displayName"].Value = baseline;
            expectedEntry.CommitChanges();
            actualEntry.CommitChanges();
            AssertPersistedBaseline(expectedEntry.Path, baseline);
            AssertPersistedBaseline(actualEntry.Path, baseline);
            var staged = $"uncommitted-display-{Guid.NewGuid():N}";
            Assert.NotEqual(baseline, staged);
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
            Assert.Equal(refresh == "description" ? staged : baseline, expectedRaw);
            comparison.Check("raw value after refresh", expectedRaw, actualRaw);
            comparison.Check("projection after refresh", expected.DisplayName, actual.DisplayName);
            comparison.Assert();
        });
    }

    private static void AssertPersistedBaseline(string path, string baseline)
    {
        // A fresh Microsoft wrapper reads each independent server object; it
        // cannot observe either provider's uncommitted in-memory cache.
        using var entry = new MsDirectory.DirectoryEntry(path, DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        Assert.Equal(baseline, entry.Properties["displayName"].Value);
    }
}
