using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using DirectorySynchronizationOptions = AdForLinux.DirectoryServices.DirectorySynchronizationOptions;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class TerminalControlTransport(List<LdapSearchCommand> opened, Func<LdapTransportControl[]> response)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Reads, Advances, CursorDisposals, Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
            => new(ResultCode.Success, "", null, command.Attributes.Contains("1.1")
                ? [TransportRow(command.BaseDn, new())] : [], [], [], []);
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        { token.ThrowIfCancellationRequested(); opened.Add(command); return ValueTask.FromResult<ILdapSearchCursor>(this); }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(0, Reads++);
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success) with { Controls = response() }, false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        { Advances++; throw new InvalidOperationException("An unpaged control query cannot continue."); }
        public ValueTask DisposeAsync() { CursorDisposals++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only control query attempted a mutation.");
        public void Dispose() => Disposals++;
    }

    private sealed class ControlRoundTripFixture : IDisposable
    {
        internal readonly DirectoryEntry Root = new("LDAP://offline.invalid/DC=example,DC=test");
        internal readonly List<LdapSearchCommand> Opened = [];
        internal readonly List<TerminalControlTransport> Transports = [];
        internal LdapTransportControl[] Response = [];
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(2, 2, startTimer: false);

        internal ControlRoundTripFixture()
        {
            Root.Options.Referral = ReferralChasingOption.None;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new TerminalControlTransport(Opened, () => Response);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        internal void AssertTwoQueriesReleased(bool streaming)
        {
            Assert.Equal(2, Opened.Count);
            Assert.Equal(streaming ? 5 : 3, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(2, Transports.Sum(transport => transport.Reads));
            Assert.Equal(2, Transports.Sum(transport => transport.CursorDisposals));
            Assert.Equal(0, Transports.Sum(transport => transport.Advances));
            Assert.Equal(0, pool.Snapshot.Total);
        }

        public void Dispose() { Root.Dispose(); pool.Dispose(); }
    }

    private static AsnReader ControlBody(LdapSearchCommand command, string oid)
        => new AsnReader(Assert.Single(command.Controls!, control => control.Oid == oid).Value,
            AsnEncodingRules.BER).ReadSequence();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_sync_roundtrip_uses_current_cookie_and_options_without_mutating_prior_request(bool replaceControl)
    {
        using var fixture = new ControlRoundTripFixture();
        var original = new DirectorySynchronization([1]);
        using var searcher = new DirectorySearcher(fixture.Root) { DirectorySynchronization = original, ReferralChasing = ReferralChasingOption.None };
        fixture.Response = [new("1.2.840.113556.1.4.841", Convert.FromHexString("300A020101020102040200FF"), false)];
        using (var results = searcher.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(new byte[] { 0, 255 }, original.GetDirectorySynchronizationCookie());
        var firstSnapshot = Assert.Single(fixture.Opened[0].Controls!).Value.ToArray();

        var current = replaceControl ? new DirectorySynchronization(new byte[] { 10 }) : original;
        current.Option = DirectorySynchronizationOptions.ObjectSecurity |
            DirectorySynchronizationOptions.ParentsFirst | DirectorySynchronizationOptions.IncrementalValues;
        searcher.DirectorySynchronization = current;
        fixture.Response = [new("1.2.840.113556.1.4.841", Convert.FromHexString("300A02010002010204020908"), false)];
        using (var results = searcher.FindAll()) Assert.Empty(results.Cast<SearchResult>());

        var before = ControlBody(fixture.Opened[0], "1.2.840.113556.1.4.841");
        Assert.Equal(0, (int)before.ReadInteger());
        _ = before.ReadInteger(); // framework default attribute-count hint is not selected by this API
        Assert.Equal(new byte[] { 1 }, before.ReadOctetString());
        before.ThrowIfNotEmpty();
        var after = ControlBody(fixture.Opened[1], "1.2.840.113556.1.4.841");
        Assert.Equal(-2147481599, (int)after.ReadInteger()); // ObjectSecurity | ParentsFirst | IncrementalValues
        _ = after.ReadInteger();
        Assert.Equal(replaceControl ? new byte[] { 10 } : new byte[] { 0, 255 }, after.ReadOctetString());
        after.ThrowIfNotEmpty();
        Assert.Equal(firstSnapshot, Assert.Single(fixture.Opened[0].Controls!).Value);
        Assert.Equal(new byte[] { 9, 8 }, current.GetDirectorySynchronizationCookie());
        if (replaceControl) Assert.Equal(new byte[] { 0, 255 }, original.GetDirectorySynchronizationCookie());
        fixture.AssertTwoQueriesReleased(streaming: false);
    }

    [Fact]
    public void Public_VLV_roundtrip_switches_target_to_offset_and_carries_only_the_returned_context()
    {
        using var fixture = new ControlRoundTripFixture();
        var view = new DirectoryVirtualListView(2, 3, "éÅ") { ApproximateTotal = 100 };
        using var searcher = new DirectorySearcher(fixture.Root) { VirtualListView = view, ReferralChasing = ReferralChasingOption.None };
        fixture.Response = [new("2.16.840.1.113730.3.4.10", Convert.FromHexString("300D02010702010A0A0100040200FF"), false)];
        using (var results = searcher.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(7, view.Offset);
        Assert.Equal(10, view.ApproximateTotal);
        var oldContext = view.DirectoryVirtualListViewContext!;
        var copiedContext = oldContext.Copy();
        var firstSnapshot = Assert.Single(fixture.Opened[0].Controls!).Value.ToArray();

        view.Target = "";
        view.Offset = 8;
        view.BeforeCount = 4;
        view.AfterCount = 5;
        fixture.Response = [new("2.16.840.1.113730.3.4.10", Convert.FromHexString("300C02010202010A0A0100040109"), false)];
        using (var results = searcher.FindAll()) Assert.Empty(results.Cast<SearchResult>());

        var before = ControlBody(fixture.Opened[0], "2.16.840.1.113730.3.4.9");
        Assert.Equal(2, (int)before.ReadInteger());
        Assert.Equal(3, (int)before.ReadInteger());
        Assert.Equal(Encoding.UTF8.GetBytes("éÅ"), before.ReadOctetString(new(TagClass.ContextSpecific, 1)));
        before.ThrowIfNotEmpty();
        var after = ControlBody(fixture.Opened[1], "2.16.840.1.113730.3.4.9");
        Assert.Equal(4, (int)after.ReadInteger());
        Assert.Equal(5, (int)after.ReadInteger());
        var offset = after.ReadSequence(new(TagClass.ContextSpecific, 0, true));
        Assert.Equal(8, (int)offset.ReadInteger());
        Assert.Equal(10, (int)offset.ReadInteger());
        offset.ThrowIfNotEmpty();
        Assert.Equal(new byte[] { 0, 255 }, after.ReadOctetString());
        after.ThrowIfNotEmpty();
        Assert.Equal(firstSnapshot, Assert.Single(fixture.Opened[0].Controls!).Value);
        Assert.Equal(new byte[] { 0, 255 }, oldContext.ContextId);
        Assert.Equal(new byte[] { 0, 255 }, copiedContext.ContextId);
        Assert.Equal(new byte[] { 9 }, view.DirectoryVirtualListViewContext!.ContextId);
        Assert.NotSame(oldContext, view.DirectoryVirtualListViewContext);
        Assert.Equal(2, view.Offset);
        Assert.Equal(10, view.ApproximateTotal);
        fixture.AssertTwoQueriesReleased(streaming: true);
    }
}
