using System.Collections;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Cached_search_failure_disposes_cursor_and_remains_visible_on_replay(bool failInCurrent)
    {
        using var entry = new DirectoryEntry("LDAP://offline.invalid/CN=item,DC=example,DC=test");
        var result = new SearchResult(entry, new ResultPropertyCollection());
        var source = new FailingSearchCursor(result, failInCurrent);
        using var results = new SearchResultCollection(new CursorSource(source), cacheResults: true);
        using var cursor = ((IEnumerable<SearchResult>)results).GetEnumerator();
        Assert.True(cursor.MoveNext());
        Assert.Same(source.Failure, Assert.Throws<InvalidOperationException>(() => cursor.MoveNext()));
        Assert.Equal(1, source.DisposeCount);

        // A cached prefix is still replayable, but must never become an apparently
        // complete result after the underlying LDAP/producer failure was observed.
        using var replay = ((IEnumerable<SearchResult>)results).GetEnumerator();
        Assert.True(replay.MoveNext());
        Assert.Same(source.Failure, Assert.Throws<InvalidOperationException>(() => replay.MoveNext()));
        Assert.Same(source.Failure, Assert.Throws<InvalidOperationException>(() => results.Count));
        results.Dispose();
        Assert.Equal(1, source.DisposeCount);
    }

    [Fact]
    public void Cached_search_completion_disposes_cursor_only_once_across_replays()
    {
        var source = new FailingSearchCursor(null, false);
        using var results = new SearchResultCollection(new CursorSource(source), cacheResults: true);
        var count = results.Count; // Exercise materialization, not just enumeration.
        Assert.Equal(0, count);
        Assert.Empty((IEnumerable<SearchResult>)results);
        Assert.Empty((IEnumerable<SearchResult>)results);
        results.Dispose();
        Assert.Equal(1, source.DisposeCount);
    }

    private sealed class CursorSource(IEnumerator<SearchResult> cursor) : IEnumerable<SearchResult>
    {
        public IEnumerator<SearchResult> GetEnumerator() => cursor;
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class FailingSearchCursor(SearchResult? result, bool failInCurrent)
        : IEnumerator<SearchResult>
    {
        internal readonly InvalidOperationException Failure = new("controlled search failure");
        internal int DisposeCount;
        private int position;
        public SearchResult Current => position == 2 && failInCurrent ? throw Failure : result!;
        object IEnumerator.Current => Current;
        public bool MoveNext()
        {
            if (result is null) return false;
            position++;
            if (position == 1) return true;
            if (position == 2) return failInCurrent ? true : throw Failure;
            return false;
        }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() => DisposeCount++;
    }
}
