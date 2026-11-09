using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class PublicCleanupFixture : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example,DC=test");
        internal readonly List<CleanupEdgeTransport> Transports = [];
        internal readonly List<string> Trace = [];
        internal readonly InvalidOperationException CleanupFailure = new("controlled cursor cleanup failure");
        internal readonly IOException OwnerFailure = new("controlled resource disposal failure");
        internal readonly IOException OperationFailure = new("controlled cursor operation failure");
        internal bool FailCursorCleanup = true;
        internal bool FailOwnerDispose;
        internal string FailureStage = "";
        internal int ExpectedPageSize;
        internal int BufferedReads, Opens, CursorReads, CursorDisposals, PageAdvances;
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(2, 2, startTimer: false);

        internal PublicCleanupFixture()
        {
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new CleanupEdgeTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        internal void AssertReleased(int resources, int queries)
        {
            AssertResourcesReleased(resources);
            Assert.Equal(1, BufferedReads); // root validation only; no row/schema materialization
            Assert.Equal(queries, Opens);
            Assert.Equal(queries, CursorReads);
            Assert.Equal(queries, CursorDisposals);
            Assert.Equal(0, PageAdvances);
        }

        internal void AssertResourcesReleased(int resources)
        {
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(FailOwnerDispose ? resources : 0, pool.Snapshot.Failures);
            Assert.Equal(0, pool.Snapshot.Total);
            Assert.Equal(0, pool.Snapshot.Waiting);
        }

        public void Dispose() { Root.Dispose(); pool.Dispose(); }
    }

    private sealed class CleanupEdgeTransport(PublicCleanupFixture fixture)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.BufferedReads++;
            Assert.Equal(new[] { "1.1" }, command.Attributes);
            return new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, new())], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(fixture.ExpectedPageSize, pageSize);
            fixture.Opens++;
            if (fixture.FailureStage == "open") throw fixture.OperationFailure;
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.CursorReads++;
            if (fixture.FailureStage == "read") throw fixture.OperationFailure;
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(
                new(ResultCode.Success, "", null, [], []), fixture.FailureStage == "page"));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        {
            fixture.PageAdvances++;
            if (fixture.FailureStage == "page") throw fixture.OperationFailure;
            throw new InvalidOperationException("A terminal query cannot advance.");
        }
        public ValueTask DisposeAsync()
        {
            fixture.CursorDisposals++;
            fixture.Trace.Add("cursor-dispose");
            if (fixture.FailCursorCleanup) throw fixture.CleanupFailure;
            return ValueTask.CompletedTask;
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only cleanup test attempted a mutation.");
        public void Dispose()
        {
            Disposals++;
            fixture.Trace.Add("owner-dispose");
            if (fixture.FailOwnerDispose) throw fixture.OwnerFailure;
        }
    }

    [Theory]
    [InlineData("find-one", false)]
    [InlineData("find-one", true)]
    [InlineData("cached-all", false)]
    [InlineData("cached-all", true)]
    [InlineData("streamed-all", false)]
    [InlineData("streamed-all", true)]
    [InlineData("cached-partial", false)]
    [InlineData("cached-partial", true)]
    public void Public_cursor_cleanup_failure_releases_every_admitted_resource_even_when_owners_throw(string path, bool ownersThrow)
    {
        using var fixture = new PublicCleanupFixture { FailOwnerDispose = ownersThrow };
        var streaming = path is "streamed-all" or "cached-partial";
        using var searcher = new DirectorySearcher(fixture.Root)
        {
            CacheResults = path != "streamed-all",
            Asynchronous = path == "cached-partial",
            ReferralChasing = ReferralChasingOption.None,
        };

        if (streaming)
        {
            using var failed = searcher.FindAll();
            Assert.Same(fixture.CleanupFailure,
                Assert.Throws<InvalidOperationException>(() => Assert.Empty(failed.Cast<SearchResult>())));
            fixture.AssertReleased(3, 1);
            if (path == "cached-partial")
            {
                Assert.Same(fixture.CleanupFailure, Assert.Throws<InvalidOperationException>(() => _ = failed.Count));
                fixture.AssertReleased(3, 1); // cached failure must not reopen or reclean a cursor
            }
        }
        else
        {
            Assert.Same(fixture.CleanupFailure, Assert.Throws<InvalidOperationException>(() =>
            {
                if (path == "find-one") _ = searcher.FindOne();
                else { using var failed = searcher.FindAll(); }
            }));
            fixture.AssertReleased(2, 1);
        }
        Assert.Equal(streaming ? new[] { "cursor-dispose", "owner-dispose", "owner-dispose" }
            : new[] { "cursor-dispose", "owner-dispose" }, fixture.Trace.TakeLast(streaming ? 3 : 2));

        // The same public searcher can admit a fresh operation after cleanup
        // failure; pool disposal errors must not strand sibling reservations.
        fixture.FailCursorCleanup = false;
        if (path == "find-one") Assert.Null(searcher.FindOne());
        else { using var repaired = searcher.FindAll(); Assert.Empty(repaired.Cast<SearchResult>()); }
        fixture.AssertReleased(streaming ? 5 : 3, 2);
    }

    [Theory]
    [InlineData("open", false)]
    [InlineData("open", true)]
    [InlineData("read", false)]
    [InlineData("read", true)]
    [InlineData("page", false)]
    [InlineData("page", true)]
    public void Public_cursor_stage_failure_preserves_error_and_releases_group_before_retry(string stage, bool streaming)
    {
        using var fixture = new PublicCleanupFixture
            { FailCursorCleanup = false, FailureStage = stage, ExpectedPageSize = 1 };
        using var searcher = new DirectorySearcher(fixture.Root)
        {
            CacheResults = !streaming,
            PageSize = 1,
            ReferralChasing = ReferralChasingOption.None,
        };

        Assert.Same(fixture.OperationFailure, Assert.Throws<IOException>(() =>
        {
            using var failed = searcher.FindAll();
            Assert.Empty(failed.Cast<SearchResult>());
        }));
        fixture.AssertResourcesReleased(streaming ? 3 : 2);
        Assert.Equal(1, fixture.BufferedReads);
        Assert.Equal(1, fixture.Opens);
        Assert.Equal(stage == "open" ? 0 : 1, fixture.CursorReads);
        Assert.Equal(stage == "open" ? 0 : 1, fixture.CursorDisposals);
        Assert.Equal(stage == "page" ? 1 : 0, fixture.PageAdvances);

        fixture.FailureStage = "";
        using (var repaired = searcher.FindAll()) Assert.Empty(repaired.Cast<SearchResult>());
        fixture.AssertResourcesReleased(streaming ? 5 : 3);
        Assert.Equal(1, fixture.BufferedReads);
        Assert.Equal(2, fixture.Opens);
        Assert.Equal(stage == "open" ? 1 : 2, fixture.CursorReads);
        Assert.Equal(stage == "open" ? 1 : 2, fixture.CursorDisposals);
        Assert.Equal(stage == "page" ? 1 : 0, fixture.PageAdvances);
    }
}
