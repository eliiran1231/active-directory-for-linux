using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Public_paged_collection_disposal_keeps_advancing_cursor_owned_until_return_and_stops_before_next_read(bool cache)
    {
        using var fixture = new InterruptedReadFixture("delayed-page");
        var roots = new List<DirectoryEntry>();
        using var searcher = new DirectorySearcher(fixture.Root)
        {
            CacheResults = cache,
            Asynchronous = cache,
            PageSize = 1,
            ReferralChasing = ReferralChasingOption.None,
            StreamingRootCreated = root => roots.Add(root),
        };
        using var results = searcher.FindAll();
        Task? disposal = null;
        try
        {
            await fixture.Waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(fixture.PageReleased.Task.IsCompleted);
            Assert.False(fixture.PageCancellation.IsCancellationRequested);
            SearchResult prefix;
            // No consumer is active during Dispose: the independent producer
            // alone is pending in NextPageAsync after accepting page one.
            using (var cursor = results.Cast<SearchResult>().GetEnumerator())
            {
                Assert.True(cursor.MoveNext());
                prefix = cursor.Current;
                Assert.Equal(42, Assert.IsType<int>(prefix.Properties["number"][0]));
            }
            Assert.Equal((1, 2, 1, 0, 1, 1),
                (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses,
                    fixture.SchemaRoots, fixture.SchemaAttributes));
            Assert.Equal(3, fixture.Transports.Count);
            Assert.Equal(1, fixture.Transports[0].Disposals); // root validation only
            Assert.All(fixture.Transports.Skip(1), transport => Assert.Equal(0, transport.Disposals));
            Assert.Equal(2, fixture.Pool.Snapshot.Total);
            Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
            Assert.False(Assert.Single(roots).IsDisposed);

            disposal = Task.Run(() => { results.Dispose(); results.Dispose(); });
            await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(fixture.PageCancellation.IsCancellationRequested);
            Assert.False(fixture.PageReleased.Task.IsCompleted);
            Assert.Equal(2, fixture.Pool.Snapshot.Total);
            Assert.All(fixture.Transports.Skip(1), transport => Assert.Equal(0, transport.Disposals));
            Assert.Equal(0, fixture.CursorCloses);
            Assert.False(Assert.Single(roots).IsDisposed);
            Assert.Throws<ObjectDisposedException>(() => results.GetEnumerator());
            Assert.Throws<ObjectDisposedException>(() => _ = results.Count);

            fixture.PageReleased.SetResult();
            await WaitForPendingPageCleanup(fixture, roots, resources: 3, queries: 1);
            Assert.Equal((1, 2, 1, 1, 1, 1),
                (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses,
                    fixture.SchemaRoots, fixture.SchemaAttributes));
            Assert.Equal(42, prefix.Properties["number"][0]);
            // No next ReadAsync or second-page schema work is allowed after the
            // cancelled continuation returns. The accepted prefix remains data.

            fixture.Failure = "";
            using (var repaired = searcher.FindAll())
                Assert.Equal(new[] { 42, 43 }, repaired.Cast<SearchResult>()
                    .Select(row => Assert.IsType<int>(row.Properties["number"][0])));
            await WaitForPendingPageCleanup(fixture, roots, resources: 5, queries: 2);
            Assert.Equal((2, 6, 2, 2, 2, 2),
                (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses,
                    fixture.SchemaRoots, fixture.SchemaAttributes));
        }
        finally
        {
            fixture.PageReleased.TrySetResult();
            if (disposal is not null) await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            results.Dispose();
            await WaitForPendingPageCleanup(fixture, roots, fixture.Transports.Count, roots.Count);
        }
        // Controlled managed cursor continuation only: no native cancellation,
        // server-send timing, concurrent consumer or Windows parity assertion.
    }

    private static async Task WaitForPendingPageCleanup(InterruptedReadFixture fixture,
        List<DirectoryEntry> roots, int resources, int queries)
    {
        // Owner Dispose precedes reservation return and cloned-root disposal.
        // Observe all boundaries before asserting exact resource counts/retry.
        await Task.Run(() => Assert.True(SpinWait.SpinUntil(() =>
            fixture.Pool.Snapshot.Total == 0 && roots.Count == queries &&
            roots.All(root => root.IsDisposed), TimeSpan.FromSeconds(5))))
            .WaitAsync(TimeSpan.FromSeconds(6));
        fixture.AssertReleased(resources);
    }
}
