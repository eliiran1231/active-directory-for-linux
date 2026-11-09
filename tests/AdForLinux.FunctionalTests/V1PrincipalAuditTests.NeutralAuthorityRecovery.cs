using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class NeutralAuthorityTransport(NeutralAuthoritySearch fixture, string host)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private string baseDn = "";
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => host;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1"))
            {
                Interlocked.Increment(ref fixture.RootReads);
                return new(ResultCode.Success, "", null, [AuthorityRow(command.BaseDn)], [], [], []);
            }
            Assert.Equal("", command.BaseDn);
            if (host == "source.invalid")
            {
                Interlocked.Increment(ref fixture.SourceSchemaReads);
                fixture.Pause("schema");
            }
            else Interlocked.Increment(ref fixture.DestinationSchemaReads);
            return new(ResultCode.Success, "", null, [], [], [], []); // strings need no advertised schema
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(0, pageSize);
            baseDn = command.BaseDn;
            if (host == "source.invalid") Interlocked.Increment(ref fixture.SourceOpens);
            else Interlocked.Increment(ref fixture.DestinationOpens);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (host == "source.invalid")
            {
                Interlocked.Increment(ref fixture.SourceReads);
                if (position == 0) fixture.Pause("cursor");
            }
            else Interlocked.Increment(ref fixture.DestinationReads);
            return ValueTask.FromResult<LdapSearchEvent>(++position switch
            {
                1 => new LdapSearchEvent.Entry(AuthorityRow(baseDn, host)),
                2 => new LdapSearchEvent.PageEnd(new(ResultCode.Success, "", null, [], []), false),
                _ => throw new InvalidOperationException("Unexpected replay after terminal response.")
            });
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Unpaged authority test advanced a page.");
        public ValueTask DisposeAsync() { Interlocked.Increment(ref fixture.CursorCloses); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Neutral search fixture attempted a write.");
        public void Dispose() => Interlocked.Increment(ref Disposals);
    }

    private static LdapTransportEntry AuthorityRow(string dn, string? host = null)
        => new(dn, host is null ? new(StringComparer.OrdinalIgnoreCase) :
            new(StringComparer.OrdinalIgnoreCase) { ["description"] = [System.Text.Encoding.UTF8.GetBytes(host)] }, []);

    private sealed class NeutralAuthoritySearch : IDisposable
    {
        internal readonly ManualResetEventSlim Entered = new(), Resume = new();
        internal readonly List<NeutralAuthorityTransport> Transports = [];
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly string Stage;
        internal int RootReads, SourceOpens, SourceReads, SourceSchemaReads, DestinationOpens, DestinationReads, DestinationSchemaReads, CursorCloses;
        internal NeutralAuthoritySearch(DirectoryEntry entry, string stage)
        {
            Stage = stage;
            entry.Close(); // remove the fixture's Protocols handles; retain its identity reader for executor proof
            entry.RefreshCache(["objectGUID", "objectSid"]); // Close discards the cached immutable proof required by the executor
            entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    Assert.Contains(options.Host, new[] { "source.invalid", "destination.invalid" });
                    var transport = new NeutralAuthorityTransport(this, options.Host!);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        internal void Pause(string stage)
        {
            if (Stage != stage) return;
            Entered.Set();
            if (!Resume.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Authority test did not release its controlled response.");
        }
        internal void AssertReleased(int resources)
        {
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, t => Assert.Equal(1, t.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Resume.Set(); Entered.Dispose(); Resume.Dispose(); Pool.Dispose(); }
    }

    [Theory]
    [InlineData("FindOne", "cursor")]
    [InlineData("FindOne", "schema")]
    [InlineData("cached FindAll", "cursor")]
    [InlineData("cached FindAll", "schema")]
    [InlineData("streamed FindAll", "cursor")]
    [InlineData("streamed FindAll", "schema")]
    [InlineData("async FindAll", "cursor")]
    [InlineData("async FindAll", "schema")]
    public async Task Neutral_late_response_after_authority_publication_refuses_rows_releases_leases_and_requires_fresh_root(string mode, string stage)
    {
        var f = new ExecutorFixture();
        using var neutral = new NeutralAuthoritySearch(f.Proof.Entry, stage);
        using var searcher = new DirectorySearcher(f.Proof.Entry)
        {
            CacheResults = mode != "streamed FindAll",
            Asynchronous = mode == "async FindAll",
            ReferralChasing = ReferralChasingOption.None,
        };
        var published = new List<SearchResult>();
        void Read()
        {
            if (mode == "FindOne") published.Add(Assert.IsType<SearchResult>(searcher.FindOne()));
            else
            {
                using var results = searcher.FindAll();
                foreach (SearchResult row in results) published.Add(row);
            }
        }
        var active = Task.Run(() => Record.Exception(Read));
        try
        {
            Assert.True(neutral.Entered.Wait(TimeSpan.FromSeconds(5)));
            using (var operation = f.Create()) operation.Execute(); // real isolated publication, not an epoch-field edit
            Assert.Equal("destination-reader", f.Proof.Entry.Username);
            Assert.Equal(0, neutral.DestinationOpens);
            neutral.Resume.Set();
            Assert.Contains("revoked", Assert.IsType<InvalidOperationException>(await active.WaitAsync(TimeSpan.FromSeconds(5))).Message);
            Assert.Empty(published);
            var paired = mode is "streamed FindAll" or "async FindAll";
            neutral.AssertReleased(paired ? 3 : 2);
            Assert.Equal(1, neutral.SourceOpens);
            Assert.Equal(stage == "cursor" || mode == "async FindAll" ? 1 : 2, neutral.SourceReads);
            Assert.Equal(stage == "schema" ? 1 : 0, neutral.SourceSchemaReads);
            Assert.Equal(1, neutral.CursorCloses);
            Assert.Equal(0, neutral.DestinationOpens);
            Assert.Equal(0, neutral.DestinationSchemaReads);

            Assert.Contains("revoked", Assert.Throws<InvalidOperationException>(Read).Message);
            neutral.AssertReleased(paired ? 3 : 2); // stale captured root cannot admit against destination
            searcher.SearchRoot = f.Proof.Entry; // explicit public reassignment acquires the new authority token
            Read();
            var result = Assert.Single(published);
            Assert.Equal("destination.invalid", result.Properties["description"][0]);
            Assert.Contains("destination.invalid", result.Path);
            neutral.AssertReleased(paired ? 6 : 4);
            Assert.Equal(2, neutral.RootReads);
            Assert.Equal((1, 2, 1, 2), (neutral.DestinationOpens, neutral.DestinationReads, neutral.DestinationSchemaReads, neutral.CursorCloses));
            Assert.Equal(0, f.Proof.Writes); // no inherited retained Protocols fallback
        }
        finally
        {
            neutral.Resume.Set();
            try { await active.WaitAsync(TimeSpan.FromSeconds(5)); }
            finally { f.Cleanup(); }
        }
    }
}
