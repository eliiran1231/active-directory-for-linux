using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Only local returned byte arrays are mutated. No directory write occurs in
// these bodies; the existing fixture still requires an authorized AD lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySearchResultBinaryOwnershipComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    // ResultsEnumerator.GetCurrentResult converts each native column anew;
    // AdsValueHelper allocates a new byte[] for ADSTYPE_OCTET_STRING. The clone
    // copies result-value arrays while retaining their mutable byte[] elements.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/Interop/AdsValueHelper2.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Repeated_enumeration_isolates_binary_value_buffers_like_microsoft(bool mutate)
    {
        var baseline = FreshMicrosoftGuid();
        Assert.Equal(SuiteCapture.Expected(16, "assert-equal-expected", 26), SuiteCapture.Expected(baseline.Length, "assert-equal-actual", 26));
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 27), SuiteCapture.Expected(FreshOurGuid(), "assert-equal-actual", 27));
        using var expectedRoot = MicrosoftEntry();
        using var actualRoot = OurEntry();
        using var expectedSearcher = Searcher(expectedRoot);
        using var actualSearcher = Searcher(actualRoot);
        using var expected = expectedSearcher.FindAll();
        using var actual = actualSearcher.FindAll();

        // Explicit cursor traversal validates exactly one row without reading
        // collection.Count or an indexer, or using LINQ count optimizations.
        // Each later Only call opens a new enumerator over the same collection.
        var leftFirst = Only<Ms.SearchResult>(expected);
        var rightFirst = Only<Ours.SearchResult>(actual);
        AssertKnown(leftFirst);
        AssertKnown(rightFirst);
        var leftBytes = Assert.IsType<byte[]>(leftFirst.Properties["objectGUID"][0]);
        var rightBytes = Assert.IsType<byte[]>(rightFirst.Properties["objectGUID"][0]);
        Assert.Equal(SuiteCapture.Expected(16, "assert-equal-expected", 44), SuiteCapture.Expected(leftBytes.Length, "assert-equal-actual", 44));
        Assert.Equal(SuiteCapture.Expected(16, "assert-equal-expected", 45), SuiteCapture.Expected(rightBytes.Length, "assert-equal-actual", 45));
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 46), SuiteCapture.Expected(leftBytes, "assert-equal-actual", 46));
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 47), SuiteCapture.Expected(rightBytes, "assert-equal-actual", 47));
        if (mutate)
        {
            leftBytes[0] ^= 0xff;
            rightBytes[0] ^= 0xff;
            Assert.NotEqual(baseline[0], leftBytes[0]);
            Assert.NotEqual(baseline[0], rightBytes[0]);
        }
        Assert.Equal(SuiteCapture.Expected(leftBytes, "assert-equal-expected", 55), SuiteCapture.Expected(rightBytes, "assert-equal-actual", 55));

        var leftSecond = Only<Ms.SearchResult>(expected);
        var rightSecond = Only<Ours.SearchResult>(actual);
        AssertKnown(leftSecond);
        AssertKnown(rightSecond);
        var leftLater = Assert.IsType<byte[]>(leftSecond.Properties["objectGUID"][0]);
        var rightLater = Assert.IsType<byte[]>(rightSecond.Properties["objectGUID"][0]);
        Assert.Equal(SuiteCapture.Expected(16, "assert-equal-expected", 63), SuiteCapture.Expected(leftLater.Length, "assert-equal-actual", 63));
        Assert.Equal(SuiteCapture.Expected(16, "assert-equal-expected", 64), SuiteCapture.Expected(rightLater.Length, "assert-equal-actual", 64));
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 65), SuiteCapture.Expected(leftLater, "assert-equal-actual", 65));
        if (!mutate) Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 66), SuiteCapture.Expected(rightLater, "assert-equal-actual", 66));

        // Fresh searchers and entries independently verify that local buffer
        // edits did not alter the server or seed a later independent query.
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 70), SuiteCapture.Expected(FreshMicrosoftGuid(), "assert-equal-actual", 70));
        Assert.Equal(SuiteCapture.Expected(baseline, "assert-equal-expected", 71), SuiteCapture.Expected(FreshOurGuid(), "assert-equal-actual", 71));
        var comparison = new Comparison($"SearchResult binary buffer ownership: mutate={mutate}")
            .Check("later binary value", Convert.ToHexString(leftLater), Convert.ToHexString(rightLater));
        if (mutate)
        {
            comparison.Check("same buffer across result enumerations", ReferenceEquals(leftBytes, leftLater),
                ReferenceEquals(rightBytes, rightLater));
        }
        comparison.Assert();
    }

    private static T Only<T>(IEnumerable results)
    {
        var cursor = results.GetEnumerator();
        try
        {
            Assert.True(cursor.MoveNext());
            var row = Assert.IsType<T>(cursor.Current);
            Assert.False(cursor.MoveNext());
            return row;
        }
        finally { (cursor as IDisposable)?.Dispose(); }
    }

    private byte[] FreshMicrosoftGuid()
    {
        using var root = MicrosoftEntry();
        using var searcher = Searcher(root);
        using var results = searcher.FindAll();
        var row = Only<Ms.SearchResult>(results);
        AssertKnown(row);
        return Assert.IsType<byte[]>(row.Properties["objectGUID"][0]).ToArray();
    }

    private byte[] FreshOurGuid()
    {
        using var root = OurEntry();
        using var searcher = Searcher(root);
        using var results = searcher.FindAll();
        var row = Only<Ours.SearchResult>(results);
        AssertKnown(row);
        return Assert.IsType<byte[]>(row.Properties["objectGUID"][0]).ToArray();
    }

    private void AssertKnown(Ms.SearchResult row) =>
        Assert.Equal(SuiteCapture.Expected(data.UserDn, "assert-equal-expected", 116), SuiteCapture.Expected(Assert.IsType<string>(row.Properties["distinguishedName"][0]), "assert-equal-actual", 116), ignoreCase: true);

    private void AssertKnown(Ours.SearchResult row) =>
        Assert.Equal(SuiteCapture.Expected(data.UserDn, "assert-equal-expected", 119), SuiteCapture.Expected(Assert.IsType<string>(row.Properties["distinguishedName"][0]), "assert-equal-actual", 119), ignoreCase: true);

    private static Ms.DirectorySearcher Searcher(Ms.DirectoryEntry root) =>
        new(root, "(objectClass=*)", new[] { "objectGUID", "distinguishedName" }, Ms.SearchScope.Base) { CacheResults = true };

    private static Ours.DirectorySearcher Searcher(Ours.DirectoryEntry root) =>
        new(root, "(objectClass=*)", new[] { "objectGUID", "distinguishedName" }, Ours.SearchScope.Base) { CacheResults = true };

    private Ms.DirectoryEntry MicrosoftEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private Ours.DirectoryEntry OurEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
