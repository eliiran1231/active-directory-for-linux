using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Disposed before RefreshCache: Microsoft's Bind throws before ADSI/DNS work.
// Retrieving the Properties wrapper itself is local, even after disposal.
[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilityFailedRefreshWrapperComparisonTests
{
    // Pinned DirectoryEntry.RefreshCache() calls Bind/GetInfo before clearing
    // _propertyCollection. A failed refresh therefore has an observable wrapper
    // lifetime contract beyond the exception type already tested elsewhere.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Failed_refresh_preserves_property_wrapper_like_microsoft(bool partial)
    {
        using var microsoft = new Ms.DirectoryEntry();
        using var ours = new Ours.DirectoryEntry();
        microsoft.Dispose();
        ours.Dispose();
        // Capture after Dispose so Unbind's deliberate wrapper reset is not
        // confused with an attempted refresh mutating state before throwing.
        var expectedOriginal = microsoft.Properties;
        var actualOriginal = ours.Properties;
        var comparison = new Comparison($"Failed RefreshCache wrapper lifetime: partial={partial}");
        comparison.Check("initial repeated getter identity", ReferenceEquals(expectedOriginal, microsoft.Properties),
            ReferenceEquals(actualOriginal, ours.Properties));
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var expectedBefore = microsoft.Properties;
            var actualBefore = ours.Properties;
            var expectedError = Record.Exception(() =>
            {
                if (partial) microsoft.RefreshCache(new[] { "description" });
                else microsoft.RefreshCache();
            });
            var actualError = Record.Exception(() =>
            {
                if (partial) ours.RefreshCache(new[] { "description" });
                else ours.RefreshCache();
            });
            Assert.IsType<ObjectDisposedException>(expectedError);
            var expectedAfter = microsoft.Properties;
            var actualAfter = ours.Properties;
            comparison.Check($"attempt {attempt}: exception", expectedError.GetType().Name, actualError?.GetType().Name)
                .Check($"attempt {attempt}: HRESULT", expectedError.HResult, actualError?.HResult)
                .Check($"attempt {attempt}: retained previous wrapper", ReferenceEquals(expectedBefore, expectedAfter),
                    ReferenceEquals(actualBefore, actualAfter))
                .Check($"attempt {attempt}: retained original wrapper", ReferenceEquals(expectedOriginal, expectedAfter),
                    ReferenceEquals(actualOriginal, actualAfter))
                .Check($"attempt {attempt}: repeated getter identity", ReferenceEquals(expectedAfter, microsoft.Properties),
                    ReferenceEquals(actualAfter, ours.Properties));
        }
        comparison.Assert();
    }
}
