using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class HeldPublicRead : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example");
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly List<HeldPublicTransport> Transports = [];
        internal readonly List<DirectoryEntry> OwnedRoots = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<LdapSearchEvent> Pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken ReadCancellation;
        internal bool Hold = true;
        internal int RootReads, Opens, Reads, SchemaReads, CursorCloses;
        internal HeldPublicRead()
        {
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new HeldPublicTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            Root.BindEntry(); // complete root setup before starting the independently owned producer
        }
        internal DirectorySearcher Searcher(bool cache) => new(Root)
        {
            CacheResults = cache, Asynchronous = cache, ReferralChasing = ReferralChasingOption.None,
            StreamingRootCreated = entry => OwnedRoots.Add(entry),
        };
        internal static LdapSearchEvent Row() => new LdapSearchEvent.Entry(TransportRow("CN=kept,DC=example", new() { ["description"] = ["kept after shutdown"] }));
        internal void AssertHeld()
        {
            Assert.False(Pending.Task.IsCompleted);
            Assert.Equal(2, Pool.Snapshot.Total);
            Assert.Equal(3, Transports.Count);
            Assert.Equal(1, Transports[0].Disposals); // prebound root validation only
            Assert.All(Transports.Skip(1), transport => Assert.Equal(0, Volatile.Read(ref transport.Disposals)));
            Assert.Equal(0, Volatile.Read(ref CursorCloses));
            Assert.False(Assert.Single(OwnedRoots).IsDisposed);
        }
        internal async Task WaitReleased(int resources, int queries)
        {
            // Pool reservation return follows resource Dispose, and owned-root
            // cleanup follows lease disposal; observe all three boundaries.
            await Task.Run(() => Assert.True(SpinWait.SpinUntil(() => Pool.Snapshot.Total == 0 &&
                OwnedRoots.Count == queries && OwnedRoots.All(root => root.IsDisposed), TimeSpan.FromSeconds(5))))
                .WaitAsync(TimeSpan.FromSeconds(6));
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.Equal(1, RootReads);
        }
        public void Dispose() { Pending.TrySetResult(Row()); Root.Dispose(); Pool.Dispose(); }
    }

    private sealed class HeldPublicTransport(HeldPublicRead fixture) : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1"))
            {
                Interlocked.Increment(ref fixture.RootReads);
                return new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, new())], [], [], []);
            }
            Assert.Equal("", command.BaseDn);
            Interlocked.Increment(ref fixture.SchemaReads);
            return new(ResultCode.Success, "", null, [], [], [], []); // no AD schema advertised
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, pageSize);
            Interlocked.Increment(ref fixture.Opens);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Interlocked.Increment(ref fixture.Reads);
            if (++position == 1)
            {
                if (!fixture.Hold) return ValueTask.FromResult(HeldPublicRead.Row());
                fixture.ReadCancellation = token;
                fixture.Entered.TrySetResult();
                // Deliberately does not complete on cancellation. This models a
                // backend call still owning its session until explicit return.
                return new(fixture.Pending.Task);
            }
            if (position != 2) throw new InvalidOperationException("A completed query was read again.");
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Unpaged shutdown fixture advanced a page.");
        public ValueTask DisposeAsync() { Interlocked.Increment(ref fixture.CursorCloses); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only shutdown fixture attempted mutation.");
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Public_collection_disposal_keeps_delayed_backend_sessions_owned_until_read_returns(bool cache)
    {
        using var fixture = new HeldPublicRead();
        using var searcher = fixture.Searcher(cache);
        using var results = searcher.FindAll();
        Task? disposal = null;
        try
        {
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            // Bound shutdown waiting on this controlled backend; finally can
            // release the backend and drain that disposal task. This is not a
            // watchdog for every possible permanent disposal deadlock.
            disposal = Task.Run(() => { results.Dispose(); results.Dispose(); });
            await disposal.WaitAsync(TimeSpan.FromSeconds(5)); // no concurrent consumer MoveNext or access
            Assert.True(fixture.ReadCancellation.IsCancellationRequested);
            fixture.AssertHeld();
            Assert.Throws<ObjectDisposedException>(() => results.GetEnumerator());
            fixture.Pending.SetResult(HeldPublicRead.Row());
            await fixture.WaitReleased(resources: 3, queries: 1);
            Assert.Equal((1, 1, 0, 1), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));

            fixture.Hold = false;
            using (var repaired = searcher.FindAll())
                Assert.Equal("kept after shutdown", Assert.Single(repaired.Cast<SearchResult>()).Properties["description"][0]);
            await fixture.WaitReleased(resources: 5, queries: 2);
            Assert.Equal((2, 3, 1, 2), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));
        }
        finally
        {
            fixture.Pending.TrySetResult(HeldPublicRead.Row());
            if (disposal is not null) await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            results.Dispose();
            await fixture.WaitReleased(resources: fixture.Transports.Count, queries: fixture.OwnedRoots.Count);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Public_streaming_results_outlive_root_and_searcher_shutdown_during_a_pending_read(bool cache, bool disposeRoot)
    {
        using var fixture = new HeldPublicRead();
        using var searcher = fixture.Searcher(cache);
        using var results = searcher.FindAll();
        Task? shutdown = null;
        try
        {
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            shutdown = Task.Run(() =>
            {
                searcher.Dispose();
                if (disposeRoot) fixture.Root.Dispose();
                else fixture.Root.Close();
            });
            await shutdown.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(disposeRoot, fixture.Root.IsDisposed);
            Assert.False(fixture.ReadCancellation.IsCancellationRequested);
            fixture.AssertHeld();
            fixture.Pending.SetResult(HeldPublicRead.Row());
            var copied = await Task.Run(() => Assert.Single(results.Cast<SearchResult>())).WaitAsync(TimeSpan.FromSeconds(5));
            await fixture.WaitReleased(resources: 3, queries: 1);
            Assert.Equal((1, 2, 1, 1), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));
            Assert.Equal("kept after shutdown", copied.Properties["description"][0]);
            Assert.Equal("LDAP://offline.invalid/CN=kept,DC=example", copied.Path);
            results.Dispose();
            Assert.Equal("kept after shutdown", copied.Properties["description"][0]);
            using var reopenedRecipe = copied.GetDirectoryEntry(); // recipe creation only, no new bind/read
            Assert.Equal(copied.Path, reopenedRecipe.Path);
            Assert.False(reopenedRecipe.IsDisposed);
            Assert.Equal(3, fixture.Transports.Count);
        }
        finally
        {
            fixture.Pending.TrySetResult(HeldPublicRead.Row());
            if (shutdown is not null) await shutdown.WaitAsync(TimeSpan.FromSeconds(5));
            results.Dispose();
            await fixture.WaitReleased(resources: 3, queries: 1);
        }
    }
}
