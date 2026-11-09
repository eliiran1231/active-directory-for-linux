using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class MalformedPublicFixture : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example");
        internal readonly DirectorySynchronization Sync = new([42]);
        internal readonly DirectorySearcher Searcher;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly List<MalformedPublicTransport> Transports = [];
        internal readonly string Mode, Fault;
        internal bool Repaired;
        internal int RootReads, Opens, Reads, SchemaReads, CursorCloses;
        internal MalformedPublicFixture(string mode, string fault)
        {
            Mode = mode; Fault = fault;
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new MalformedPublicTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            Root.BindEntry();
            Searcher = new(Root)
            {
                CacheResults = mode != "streamed FindAll", Asynchronous = mode == "async FindAll",
                SizeLimit = 1, DirectorySynchronization = Sync, ReferralChasing = ReferralChasingOption.None,
            };
        }
        internal void AssertReleased(int resources)
        {
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.Equal(1, RootReads);
        }
        public void Dispose() { Searcher.Dispose(); Root.Dispose(); Pool.Dispose(); }
    }

    private sealed class MalformedPublicTransport(MalformedPublicFixture fixture)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
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
            return new(ResultCode.Success, "", null, [], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(0, pageSize);
            Assert.Equal(1, command.SizeLimit);
            Assert.Single(Assert.IsType<LdapTransportControl[]>(command.Controls), c => c.Oid == "1.2.840.113556.1.4.841");
            Interlocked.Increment(ref fixture.Opens);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Interlocked.Increment(ref fixture.Reads);
            if (++position == 1)
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(TransportRow("CN=first,DC=example",
                    new() { ["description"] = [fixture.Repaired ? "recovered" : "first valid"] })));
            if (position != 2) throw new InvalidOperationException("No operation may read after the controlled fault or terminal.");
            if (!fixture.Repaired && fixture.Fault == "excess-entry")
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(TransportRow("CN=excess,DC=example",
                    new() { ["description"] = ["must never be published"] })));
            if (!fixture.Repaired && fixture.Fault == "missing-terminal")
                return ValueTask.FromResult<LdapSearchEvent>(null!); // documented EOF-without-PageEnd failure boundary
            var control = !fixture.Repaired && fixture.Fault == "malformed-control"
                ? new LdapTransportControl("1.2.840.113556.1.4.841", [0x30, 0x00], false)
                : new LdapTransportControl("1.2.840.113556.1.4.841", Convert.FromHexString("3009020101020102040109"), false);
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(
                new(ResultCode.Success, "", null, [], [control]), !fixture.Repaired && fixture.Fault == "unpaged-continuation"));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Malformed unpaged response caused page dispatch.");
        public ValueTask DisposeAsync() { Interlocked.Increment(ref fixture.CursorCloses); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only malformed-response fixture attempted mutation.");
        public void Dispose() => Disposals++;
    }

    public static IEnumerable<object[]> PublicMalformedResponseCases()
        => from mode in new[] { "FindOne", "cached FindAll", "streamed FindAll", "async FindAll" }
           from fault in new[] { "excess-entry", "missing-terminal", "unpaged-continuation", "malformed-control" }
           select new object[] { mode, fault };

    [Theory]
    [MemberData(nameof(PublicMalformedResponseCases))]
    public async Task Public_malformed_cursor_response_limits_publication_preserves_cookie_and_allows_clean_retry(string mode, string fault)
    {
        using var fixture = new MalformedPublicFixture(mode, fault);
        SearchResultCollection? failed = null;
        var published = new List<SearchResult>();
        try
        {
            var error = await Task.Run(() => Record.Exception(() =>
            {
                if (mode == "FindOne") published.Add(Assert.IsType<SearchResult>(fixture.Searcher.FindOne()));
                else
                {
                    failed = fixture.Searcher.FindAll();
                    foreach (SearchResult row in failed) published.Add(row);
                }
            })).WaitAsync(TimeSpan.FromSeconds(5));
            if (fault == "malformed-control") Assert.IsType<BerConversionException>(error);
            else
                Assert.Equal(fault switch
                {
                    "excess-entry" => "LDAP search exceeded its total entry limit.",
                    "missing-terminal" => "Search ended without a result envelope.",
                    _ => "Unpaged search returned a continuation.",
                }, Assert.IsType<InvalidOperationException>(error).Message);
            var partial = mode == "async FindAll";
            if (partial) Assert.Equal("first valid", Assert.Single(published).Properties["description"][0]);
            else Assert.Empty(published);
            Assert.Equal(new byte[] { 42 }, fixture.Sync.GetDirectorySynchronizationCookie());
            Assert.Equal((1, 2, partial ? 1 : 0, 1), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));
            var paired = mode is "streamed FindAll" or "async FindAll";
            fixture.AssertReleased(paired ? 3 : 2);
            if (partial)
            {
                var cachedFailure = Assert.IsType<SearchResultCollection>(failed);
                using var replay = cachedFailure.Cast<SearchResult>().GetEnumerator();
                Assert.True(replay.MoveNext());
                Assert.Equal("first valid", replay.Current.Properties["description"][0]);
                Assert.Same(error, Record.Exception(() => replay.MoveNext()));
                Assert.Same(error, Record.Exception(() => _ = cachedFailure.Count));
                fixture.AssertReleased(3);
                Assert.Equal((1, 2, 1, 1), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));
            }

            fixture.Repaired = true;
            SearchResult recovered;
            if (mode == "FindOne") recovered = Assert.IsType<SearchResult>(fixture.Searcher.FindOne());
            else
            {
                using var results = fixture.Searcher.FindAll();
                recovered = Assert.Single(results.Cast<SearchResult>());
            }
            Assert.Equal("recovered", recovered.Properties["description"][0]);
            Assert.Equal(new byte[] { 9 }, fixture.Sync.GetDirectorySynchronizationCookie());
            Assert.Equal((2, 4, partial ? 2 : 1, 2), (fixture.Opens, fixture.Reads, fixture.SchemaReads, fixture.CursorCloses));
            fixture.AssertReleased(paired ? 5 : 3);
        }
        finally { failed?.Dispose(); }
    }
}
