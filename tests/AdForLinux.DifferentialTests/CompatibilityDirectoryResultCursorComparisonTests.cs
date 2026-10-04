using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Fixture setup/cleanup requires a separately authorized disposable AD lab.
// These probes only read the fixture's exact user DN; they do not mutate it.
[Collection("differential")]
[Trait("Category", "DirectoryResultCursorLive")]
public sealed class CompatibilityDirectoryResultCursorComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData(true, "before-first")]
    [InlineData(false, "before-first")]
    [InlineData(true, "positioned")]
    [InlineData(false, "positioned")]
    [InlineData(true, "after-last")]
    [InlineData(false, "after-last")]
    [InlineData(true, "empty-after-last")]
    [InlineData(false, "empty-after-last")]
    public void Current_validates_cursor_position(bool cacheResults, string position)
    {
        WithResults(cacheResults, position == "empty-after-last", (expected, actual) =>
        {
            var left = expected.GetEnumerator();
            var right = actual.GetEnumerator();
            try
            {
                Position(left, position);
                Position(right, position);
                var comparison = new Comparison($"Directory results Current: cache={cacheResults}, {position}");
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    var expectedState = ReadCurrent(left);
                    var actualState = ReadCurrent(right);
                    if (position == "positioned")
                    {
                        Assert.Null(expectedState.Error);
                        Assert.Equal(data.UserDn, expectedState.Dn, StringComparer.OrdinalIgnoreCase);
                    }
                    else Assert.Equal(typeof(InvalidOperationException), expectedState.Error);
                    comparison.Check($"read {attempt}: error", expectedState.Error, actualState.Error)
                        .Check($"read {attempt}: DN", expectedState.Dn?.ToUpperInvariant(), actualState.Dn?.ToUpperInvariant());
                }
                comparison.Assert();
            }
            finally { Dispose(left); Dispose(right); }
        });
    }

    [Theory]
    [InlineData(false, "before-first")]
    [InlineData(true, "before-first")]
    [InlineData(false, "positioned")]
    [InlineData(true, "positioned")]
    [InlineData(false, "after-last")]
    [InlineData(true, "after-last")]
    public void Reset_rewinds_cached_results_after_optional_materialization(bool materialize, string position)
    {
        WithResults(true, false, (expected, actual) =>
        {
            if (materialize)
            {
                // Read Count specifically: Assert.Single would enumerate and
                // would not exercise the materialized collection state.
                var expectedCount = expected.Count;
                var actualCount = actual.Count;
                Assert.Equal(1, expectedCount);
                Assert.Equal(1, actualCount);
            }
            var left = expected.GetEnumerator();
            var right = actual.GetEnumerator();
            try
            {
                Position(left, position);
                Position(right, position);
                var leftError = Record.Exception(left.Reset);
                var rightError = Record.Exception(right.Reset);
                Assert.Null(leftError);
                var comparison = new Comparison($"Directory results Reset: materialized={materialize}, {position}")
                    .Check("Reset error", leftError?.GetType(), rightError?.GetType());

                // Verify the oracle's complete rewind even when the clone
                // rejected Reset. Only replay the clone if its Reset succeeded.
                Assert.Equal(typeof(InvalidOperationException), ReadCurrent(left).Error);
                Assert.True(left.MoveNext());
                var replay = ReadCurrent(left);
                Assert.Null(replay.Error);
                Assert.Equal(data.UserDn, replay.Dn, StringComparer.OrdinalIgnoreCase);
                Assert.False(left.MoveNext());
                if (rightError is null)
                {
                    comparison.Check("Current after Reset", typeof(InvalidOperationException), ReadCurrent(right).Error);
                    var moved = right.MoveNext();
                    comparison.Check("replay first MoveNext", true, moved);
                    if (moved)
                    {
                        var actualReplay = ReadCurrent(right);
                        comparison.Check("replay Current error", replay.Error, actualReplay.Error)
                            .Check("replay DN", replay.Dn?.ToUpperInvariant(), actualReplay.Dn?.ToUpperInvariant());
                    }
                    comparison.Check("replay end", false, right.MoveNext());
                }
                comparison.Assert();
            }
            finally { Dispose(left); Dispose(right); }
        });
    }

    private void WithResults(bool cacheResults, bool empty, Action<Ms.SearchResultCollection, Ours.SearchResultCollection> action)
    {
        using var leftRoot = new Ms.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var rightRoot = new Ours.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        using var leftSearch = new Ms.DirectorySearcher(leftRoot)
            { SearchScope = Ms.SearchScope.Base, Filter = "(objectClass=*)", CacheResults = cacheResults };
        using var rightSearch = new Ours.DirectorySearcher(rightRoot)
            { SearchScope = Ours.SearchScope.Base, Filter = "(objectClass=*)", CacheResults = cacheResults };
        leftSearch.PropertiesToLoad.Add("distinguishedName");
        rightSearch.PropertiesToLoad.Add("distinguishedName");

        // A separate positive query proves root, credentials and projection
        // before even the empty-result probe. It does not materialize the
        // collections under test or share an outstanding native search handle.
        using (var probe = leftSearch.FindAll())
            Assert.Equal(new[] { data.UserDn }, probe.Cast<Ms.SearchResult>().Select(row =>
                (string)row.Properties["distinguishedName"][0]!), StringComparer.OrdinalIgnoreCase);
        using (var probe = rightSearch.FindAll())
            Assert.Equal(new[] { data.UserDn }, probe.Cast<Ours.SearchResult>().Select(row =>
                (string)row.Properties["distinguishedName"][0]!), StringComparer.OrdinalIgnoreCase);
        if (empty)
        {
            leftSearch.Filter = "(!(objectClass=*))";
            rightSearch.Filter = "(!(objectClass=*))";
        }
        using var expected = leftSearch.FindAll();
        using var actual = rightSearch.FindAll();
        action(expected, actual);
    }

    private static void Position(IEnumerator cursor, string position)
    {
        if (position == "before-first") return;
        if (position == "empty-after-last") { Assert.False(cursor.MoveNext()); return; }
        Assert.True(cursor.MoveNext());
        if (position == "after-last") Assert.False(cursor.MoveNext());
    }

    private static (Type? Error, string? Dn) ReadCurrent(IEnumerator cursor)
    {
        string? dn = null;
        var error = Record.Exception(() => dn = cursor.Current switch
        {
            Ms.SearchResult row => (string)row.Properties["distinguishedName"][0]!,
            Ours.SearchResult row => (string)row.Properties["distinguishedName"][0]!,
            null => null,
            _ => throw new InvalidOperationException("Unexpected cursor element type."),
        });
        return (error?.GetType(), dn);
    }

    private static void Dispose(IEnumerator cursor) => (cursor as IDisposable)?.Dispose();
}
