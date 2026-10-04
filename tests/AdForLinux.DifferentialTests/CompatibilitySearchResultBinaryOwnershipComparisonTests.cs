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
        Assert.Equal(16, baseline.Length);
        Assert.Equal(baseline, FreshOurGuid());
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
        Assert.Equal(16, leftBytes.Length);
        Assert.Equal(16, rightBytes.Length);
        Assert.Equal(baseline, leftBytes);
        Assert.Equal(baseline, rightBytes);
        if (mutate)
        {
            leftBytes[0] ^= 0xff;
            rightBytes[0] ^= 0xff;
            Assert.NotEqual(baseline[0], leftBytes[0]);
            Assert.NotEqual(baseline[0], rightBytes[0]);
        }
        Assert.Equal(leftBytes, rightBytes);

        var leftSecond = Only<Ms.SearchResult>(expected);
        var rightSecond = Only<Ours.SearchResult>(actual);
        AssertKnown(leftSecond);
        AssertKnown(rightSecond);
        var leftLater = Assert.IsType<byte[]>(leftSecond.Properties["objectGUID"][0]);
        var rightLater = Assert.IsType<byte[]>(rightSecond.Properties["objectGUID"][0]);
        Assert.Equal(16, leftLater.Length);
        Assert.Equal(16, rightLater.Length);
        Assert.Equal(baseline, leftLater);
        if (!mutate) Assert.Equal(baseline, rightLater);

        // Fresh searchers and entries independently verify that local buffer
        // edits did not alter the server or seed a later independent query.
        Assert.Equal(baseline, FreshMicrosoftGuid());
        Assert.Equal(baseline, FreshOurGuid());
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
        Assert.Equal(data.UserDn, Assert.IsType<string>(row.Properties["distinguishedName"][0]), ignoreCase: true);

    private void AssertKnown(Ours.SearchResult row) =>
        Assert.Equal(data.UserDn, Assert.IsType<string>(row.Properties["distinguishedName"][0]), ignoreCase: true);

    private static Ms.DirectorySearcher Searcher(Ms.DirectoryEntry root) =>
        new(root, "(objectClass=*)", new[] { "objectGUID", "distinguishedName" }, Ms.SearchScope.Base) { CacheResults = true };

    private static Ours.DirectorySearcher Searcher(Ours.DirectoryEntry root) =>
        new(root, "(objectClass=*)", new[] { "objectGUID", "distinguishedName" }, Ours.SearchScope.Base) { CacheResults = true };

    private Ms.DirectoryEntry MicrosoftEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private Ours.DirectoryEntry OurEntry() => new(DifferentialSettings.PathFor(data.UserDn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
