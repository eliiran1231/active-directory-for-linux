using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class InterruptedReadFixture : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example");
        internal readonly List<InterruptedReadTransport> Transports = [];
        internal readonly IOException SchemaFailure = new("controlled later-row schema failure");
        internal readonly TaskCompletionSource Waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource PageReleased = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken PageCancellation;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal string Failure = "";
        internal int RootReads, SchemaRoots, SchemaAttributes, Opens, Reads, Pages, CursorCloses, ResourceCloses;

        internal InterruptedReadFixture(string failure)
        {
            Failure = failure;
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new InterruptedReadTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        internal void AssertReleased(int resources)
        {
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(resources, ResourceCloses);
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.Equal(1, RootReads);
        }

        public void Dispose() { PageReleased.TrySetResult(); Root.Dispose(); Pool.Dispose(); }
    }

    private sealed class InterruptedReadTransport(InterruptedReadFixture fixture)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1"))
            {
                Interlocked.Increment(ref fixture.RootReads);
                return new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, new())], [], [], []);
            }
            LdapTransportEntry row;
            if (command.BaseDn == "")
            {
                Interlocked.Increment(ref fixture.SchemaRoots);
                row = TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] });
            }
            else
            {
                Interlocked.Increment(ref fixture.SchemaAttributes);
                var later = command.Filter.Contains("laterNumber", StringComparison.Ordinal);
                if (fixture.Failure == "schema" && later) throw fixture.SchemaFailure;
                row = TransportRow("CN=number,CN=Schema", new() { ["lDAPDisplayName"] = [later ? "laterNumber" : "number"],
                    ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] });
            }
            return new(ResultCode.Success, "", null, [row], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(1, pageSize);
            Interlocked.Increment(ref fixture.Opens);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public async ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Interlocked.Increment(ref fixture.Reads);
            switch (++position)
            {
                case 1: return new LdapSearchEvent.Entry(TransportRow("CN=first,DC=example", new() { ["number"] = ["42"] }));
                case 2: return new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true);
                case 3:
                    if (fixture.Failure == "blocked-read")
                    {
                        fixture.Waiting.TrySetResult();
                        await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, token);
                        throw new InvalidOperationException("Cancelled read resumed without cancellation.");
                    }
                    return new LdapSearchEvent.Entry(TransportRow("CN=second,DC=example", new() {
                        [fixture.Failure is "schema" or "repaired-schema" ? "laterNumber" : "number"] =
                            [fixture.Failure == "conversion" ? "2147483648" : "43"] }));
                case 4: return new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false);
                default: throw new InvalidOperationException("No read is permitted after terminal cleanup.");
            }
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        {
            token.ThrowIfCancellationRequested();
            Interlocked.Increment(ref fixture.Pages);
            if (fixture.Failure == "delayed-page")
            {
                fixture.PageCancellation = token;
                fixture.Waiting.TrySetResult();
                // A continuation may still own its cursor while cancellation is
                // signaled. Explicit return, not cancellation alone, ends it.
                return new ValueTask(fixture.PageReleased.Task);
            }
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync() { Interlocked.Increment(ref fixture.CursorCloses); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only interruption fixture attempted mutation.");
        public void Dispose()
        {
            Interlocked.Increment(ref Disposals);
            if (Interlocked.Increment(ref fixture.ResourceCloses) == 3) fixture.Released.TrySetResult();
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Public_collection_disposal_cancels_inflight_read_releases_pair_and_allows_retry(bool cache, bool partial)
    {
        using var fixture = new InterruptedReadFixture("blocked-read");
        using var searcher = new DirectorySearcher(fixture.Root) { CacheResults = cache,
            Asynchronous = partial, PageSize = 1, ReferralChasing = ReferralChasingOption.None };
        // Cached synchronous FindAll cannot expose its collection before the
        // producer finishes, so it has no public mid-read Dispose operation.
        var results = searcher.FindAll();
        try
        {
            await fixture.Waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var cursor = results.Cast<SearchResult>().GetEnumerator();
            Assert.True(cursor.MoveNext());
            Assert.Equal(42, Assert.IsType<int>(cursor.Current.Properties["number"][0]));
            results.Dispose();
            results.Dispose();
            await fixture.Released.Task.WaitAsync(TimeSpan.FromSeconds(5));
            // Resource Dispose signals before the pool's reservation-return
            // finally block; wait for that observable boundary as well.
            Assert.True(SpinWait.SpinUntil(() => fixture.Pool.Snapshot.Total == 0, TimeSpan.FromSeconds(5)));
            fixture.AssertReleased(3);
            Assert.Equal((1, 3, 1, 1, 1, 1),
                (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses, fixture.SchemaRoots, fixture.SchemaAttributes));
        }
        finally { results.Dispose(); }

        fixture.Failure = "";
        using (var repaired = searcher.FindAll())
            Assert.Equal(new[] { 42, 43 }, repaired.Cast<SearchResult>().Select(r => Assert.IsType<int>(r.Properties["number"][0])));
        fixture.AssertReleased(5);
        Assert.Equal((2, 7, 2, 2, 2, 2),
            (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses, fixture.SchemaRoots, fixture.SchemaAttributes));
    }

    [Theory]
    [InlineData("conversion", false)]
    [InlineData("conversion", true)]
    [InlineData("schema", false)]
    [InlineData("schema", true)]
    public async Task Public_later_row_failure_preserves_published_prefix_and_cached_error_before_healthy_retry(string stage, bool cache)
    {
        using var fixture = new InterruptedReadFixture(stage);
        using var searcher = new DirectorySearcher(fixture.Root) { CacheResults = cache,
            Asynchronous = cache, PageSize = 1, ReferralChasing = ReferralChasingOption.None };
        using var failed = searcher.FindAll();
        Exception failure = await Task.Run(() =>
        {
            using var cursor = failed.Cast<SearchResult>().GetEnumerator();
            Assert.True(cursor.MoveNext());
            Assert.Equal(42, Assert.IsType<int>(cursor.Current.Properties["number"][0]));
            var error = Record.Exception(() => cursor.MoveNext());
            if (stage == "schema") Assert.Same(fixture.SchemaFailure, error);
            else Assert.IsType<OverflowException>(error);
            return error!;
        }).WaitAsync(TimeSpan.FromSeconds(5));
        fixture.AssertReleased(3);
        Assert.Equal((1, cache ? 3 : 4, 1, 1, 1, stage == "schema" ? 2 : 1),
            (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses, fixture.SchemaRoots, fixture.SchemaAttributes));
        if (cache)
        {
            using var replay = failed.Cast<SearchResult>().GetEnumerator();
            Assert.True(replay.MoveNext());
            Assert.Equal(42, replay.Current.Properties["number"][0]);
            Assert.Same(failure, Record.Exception(() => replay.MoveNext()));
            Assert.Same(failure, Record.Exception(() => _ = failed.Count));
            Assert.Equal(1, fixture.Opens);
            Assert.Equal(1, fixture.CursorCloses);
        }

        fixture.Failure = stage == "schema" ? "repaired-schema" : "";
        using (var repaired = searcher.FindAll())
            Assert.Equal(new[] { 42, 43 }, repaired.Cast<SearchResult>()
                .Select(r => Assert.IsType<int>(r.Properties[r.Properties.Contains("laterNumber") ? "laterNumber" : "number"][0])));
        fixture.AssertReleased(5);
        Assert.Equal((2, cache ? 7 : 8, 2, 2, 2, stage == "schema" ? 4 : 2),
            (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses, fixture.SchemaRoots, fixture.SchemaAttributes));
    }
}
