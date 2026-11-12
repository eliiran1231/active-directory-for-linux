using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class DirectoryConversationProbe(IEnumerable<LdapSearchEvent> script)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        private readonly Queue<LdapSearchEvent> events = new(script);
        internal readonly List<LdapSearchCommand> BufferedRequests = [];
        internal int Opens, Reads, PageAdvances, CursorDisposals, Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch |
            LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            BufferedRequests.Add(command);
            return new(ResultCode.Success, "", null, command.Attributes.Contains("1.1")
                ? [TransportRow(command.BaseDn, new())] : [], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        { token.ThrowIfCancellationRequested(); Opens++; return ValueTask.FromResult<ILdapSearchCursor>(this); }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        { token.ThrowIfCancellationRequested(); Reads++; return ValueTask.FromResult(events.Dequeue()); }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        { token.ThrowIfCancellationRequested(); PageAdvances++; return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { CursorDisposals++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only probe received a mutation.");
        public void Dispose() => Disposals++;
    }

    private sealed class DirectoryConversationFixture(IEnumerable<LdapSearchEvent> script) : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example,DC=test");
        internal readonly List<DirectoryConversationProbe> Transports = [];
        internal readonly List<(string Host, int Count, ReferralChasingOption Referrals)> Admissions = [];
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);

        internal DirectorySearcher Searcher(bool cached, bool partial, int pageSize = 0)
        {
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Admissions.Add((options.Host, count, referrals));
                return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new DirectoryConversationProbe(script);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            };
            return new DirectorySearcher(Root) { CacheResults = cached, Asynchronous = partial,
                PageSize = pageSize, ReferralChasing = ReferralChasingOption.None };
        }

        internal void AssertReleased(int expectedSessions, int expectedReads, int expectedPages)
        {
            Assert.Equal(expectedSessions, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(1, Transports.Sum(transport => transport.Opens));
            Assert.Equal(expectedReads, Transports.Sum(transport => transport.Reads));
            Assert.Equal(expectedPages, Transports.Sum(transport => transport.PageAdvances));
            Assert.Equal(1, Transports.Sum(transport => transport.CursorDisposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.All(Admissions, admission =>
            {
                Assert.Equal("offline.invalid", admission.Host);
                Assert.Equal(ReferralChasingOption.None, admission.Referrals);
            });
        }

        public void Dispose() { Root.Dispose(); Pool.Dispose(); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Public_neutral_referrals_never_open_a_returned_authority_and_preserve_terminal_error(bool partial, bool referralResult)
    {
        var code = referralResult ? ResultCode.Referral : ResultCode.Success;
        using var fixture = new DirectoryConversationFixture([
            new LdapSearchEvent.Entry(TransportRow("CN=known,DC=example,DC=test", new() { ["cn"] = ["known"] })),
            new LdapSearchEvent.Reference(new(["ldap://other-authority.invalid/DC=foreign"], [])),
            new LdapSearchEvent.PageEnd(Envelope(code) with { Referrals = ["ldap://another-authority.invalid/DC=foreign"] }, false),
        ]);
        using var searcher = fixture.Searcher(cached: false, partial);
        using var results = searcher.FindAll();
        var rows = new List<SearchResult>();
        var failure = Record.Exception(() => { foreach (SearchResult row in results) rows.Add(row); });

        Assert.Equal(referralResult && !partial ? 0 : 1, rows.Count);
        if (referralResult)
            Assert.Equal((int)ResultCode.Referral, Assert.IsType<DirectoryServicesCOMException>(failure).ExtendedError);
        else Assert.Null(failure);
        Assert.All(rows, row => Assert.Equal("known", row.Properties["cn"][0]));
        fixture.AssertReleased(expectedSessions: 3, expectedReads: 3, expectedPages: 0);
        Assert.Equal(new[] { 1, 2 }, fixture.Admissions.Select(admission => admission.Count));
        var requests = fixture.Transports.SelectMany(transport => transport.BufferedRequests).ToArray();
        Assert.Equal(referralResult && !partial ? 1 : 2, requests.Length);
        Assert.All(requests, request => Assert.Contains(request.BaseDn, new[] { "", "DC=example,DC=test" }));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Malformed_later_page_control_keeps_only_contractually_visible_rows_and_never_replays(bool cached, bool partial)
    {
        using var fixture = new DirectoryConversationFixture([
            new LdapSearchEvent.Entry(TransportRow("CN=first,DC=example,DC=test", new() { ["cn"] = ["first"] })),
            new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success) with {
                Controls = [new("1.2.840.113556.1.4.319", Convert.FromHexString("3006020101040101"), false)] }, true),
            new LdapSearchEvent.Entry(TransportRow("CN=second,DC=example,DC=test", new() { ["cn"] = ["second"] })),
            new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success) with {
                Controls = [new("1.2.840.113556.1.4.319", [0x30, 0], false)] }, false),
        ]);
        using var searcher = fixture.Searcher(cached, partial, pageSize: 1);
        if (cached && !partial)
        {
            Assert.Throws<BerConversionException>(() => searcher.FindAll());
            fixture.AssertReleased(expectedSessions: 2, expectedReads: 4, expectedPages: 1);
            Assert.Single(fixture.Transports.SelectMany(transport => transport.BufferedRequests));
            return;
        }

        using var results = searcher.FindAll();
        var rows = new List<SearchResult>();
        var failure = Assert.IsType<BerConversionException>(Record.Exception(() =>
        {
            foreach (SearchResult row in results) rows.Add(row);
        }));
        Assert.Equal(partial ? new[] { "first", "second" } : new[] { "first" },
            rows.Select(row => (string)row.Properties["cn"][0]));
        fixture.AssertReleased(expectedSessions: 3, expectedReads: 4, expectedPages: 1);
        if (cached)
        {
            var replay = new List<SearchResult>();
            Assert.Same(failure, Assert.Throws<BerConversionException>(() =>
            {
                foreach (SearchResult row in results) replay.Add(row);
            }));
            Assert.Equal(rows.Select(row => row.Path), replay.Select(row => row.Path));
            Assert.Same(failure, Assert.Throws<BerConversionException>(() => _ = results.Count));
            fixture.AssertReleased(expectedSessions: 3, expectedReads: 4, expectedPages: 1);
        }
    }
}
