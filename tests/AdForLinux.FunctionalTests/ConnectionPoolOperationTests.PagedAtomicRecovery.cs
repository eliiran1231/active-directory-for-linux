using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class AtomicPageOwner(Action close) : IDisposable
    {
        private Action? close = close;
        internal int Disposals;
        public void Dispose() { if (Interlocked.Exchange(ref close, null) is { } action) { Disposals++; action(); } }
    }

    private sealed class AtomicPageFixture : IDisposable
    {
        internal readonly DirectoryEntry Root = RestrictedRecipe().CreateDirectoryEntry("DC=example");
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, AtomicPageTransport> Pool = new(2, 2, startTimer: false);
        internal readonly List<AtomicPageTransport> Transports = [];
        internal readonly List<AtomicPageOwner> Owners = [];
        internal readonly List<int> Admissions = [];
        internal readonly List<(AtomicPageTransport Transport, string Stage)> SchemaReads = [];
        internal readonly IOException SchemaFailure = new("controlled schema failure on the second accepted page");
        internal bool Repaired;
        internal readonly string Fault;
        internal int Opens, Reads, Pages, CursorCloses;
        internal AtomicPageFixture(string fault)
        {
            Fault = fault;
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Admissions.Add(count);
                var leases = Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new AtomicPageTransport(this); Transports.Add(transport); return transport;
                }, reusable: false);
                var owner = new AtomicPageOwner(() => { foreach (var lease in leases) lease.Dispose(); });
                Owners.Add(owner);
                foreach (var lease in leases) lease.Value.Owner = owner;
                return LdapRestrictedOperation.Wrap(leases.Select(lease => (ILdapRequestTransport)lease.Value).ToArray(), owner, options);
            };
        }
        internal void AssertReleased(int resources, int groups)
        {
            Assert.Equal(resources, Transports.Count); Assert.Equal(groups, Owners.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.All(Owners, owner => Assert.Equal(1, owner.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total); Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Root.Dispose(); Pool.Dispose(); }
    }

    private sealed class AtomicPageTransport(AtomicPageFixture fixture) : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal AtomicPageOwner Owner = null!;
        internal int Disposals;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => "directory.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, Owner.Disposals);
            if (command.Attributes.Contains("1.1")) return Success(TransportRow(command.BaseDn, new()));
            if (command.BaseDn == "")
            {
                fixture.SchemaReads.Add((this, "root"));
                return Success(TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] }));
            }
            Assert.Equal("CN=Schema", command.BaseDn);
            var later = command.Filter.Contains("laterNumber", StringComparison.Ordinal);
            fixture.SchemaReads.Add((this, later ? "later" : "first"));
            if (later && !fixture.Repaired && fixture.Fault == "schema") throw fixture.SchemaFailure;
            return Success(TransportRow("CN=number,CN=Schema", new() { ["lDAPDisplayName"] = [later ? "laterNumber" : "number"],
                ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] }));
        }
        private static LdapSearchResult Success(params LdapTransportEntry[] rows) => new(ResultCode.Success, "", null, rows, [], [], []);
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(1, pageSize); Assert.Equal(3, command.SizeLimit);
            Assert.Equal(0, Owner.Disposals); fixture.Opens++;
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, Owner.Disposals); fixture.Reads++;
            return ValueTask.FromResult<LdapSearchEvent>(++position switch
            {
                1 => new LdapSearchEvent.Entry(TransportRow("CN=first,DC=example", new() { ["number"] = ["42"] })),
                2 => new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true),
                3 => new LdapSearchEvent.Entry(TransportRow("CN=second,DC=example", new() {
                    ["laterNumber;range=0-1"] = ["43", !fixture.Repaired && fixture.Fault == "conversion" ? "2147483648" : "44"] })),
                4 => new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true),
                5 => new LdapSearchEvent.Entry(TransportRow("CN=third,DC=example", new() { ["number"] = ["45"] })),
                6 => new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false),
                _ => throw new InvalidOperationException("Read after a terminal result.")
            });
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, Owner.Disposals); fixture.Pages++;
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync() { fixture.CursorCloses++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only atomic page fixture attempted mutation.");
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData("schema")]
    [InlineData("conversion")]
    public async Task Restricted_public_buffered_paging_stops_before_third_page_on_second_page_schema_or_value_failure_and_restarts_cleanly(string fault)
    {
        using var fixture = new AtomicPageFixture(fault);
        using var searcher = new DirectorySearcher(fixture.Root) { PageSize = 1, SizeLimit = 3, CacheResults = true,
            ReferralChasing = ReferralChasingOption.None };
        var returned = false;
        var error = await Task.Run(() => Record.Exception(() =>
        {
            using var results = searcher.FindAll(); returned = true;
        })).WaitAsync(TimeSpan.FromSeconds(5));
        if (fault == "schema") Assert.Same(fixture.SchemaFailure, error);
        else Assert.IsType<OverflowException>(error);
        Assert.False(returned); // first accepted page cannot escape a failed buffered collection
        Assert.Equal(new[] { 1, 2 }, fixture.Admissions);
        Assert.Equal((1, 4, 1, 1), (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses));
        Assert.Equal(new[] { "root", "first", "later" }, fixture.SchemaReads.Select(r => r.Stage));
        Assert.All(fixture.SchemaReads, read => Assert.Same(fixture.Transports[2], read.Transport));
        fixture.AssertReleased(resources: 3, groups: 2);

        fixture.Repaired = true;
        using var repaired = searcher.FindAll();
        var rows = repaired.Cast<SearchResult>().ToArray();
        Assert.Equal(3, rows.Length);
        Assert.Equal(42, Assert.IsType<int>(rows[0].Properties["number"][0]));
        Assert.Equal(new[] { 43, 44 }, rows[1].Properties["laterNumber;range=0-1"].Cast<int>());
        Assert.False(rows[1].Properties.Contains("laterNumber"));
        Assert.Equal(45, Assert.IsType<int>(rows[2].Properties["number"][0]));
        Assert.Equal(new[] { 1, 2, 2 }, fixture.Admissions);
        Assert.Equal((2, 10, 3, 2), (fixture.Opens, fixture.Reads, fixture.Pages, fixture.CursorCloses));
        Assert.Equal(new[] { "root", "first", "later", "root", "first", "later" }, fixture.SchemaReads.Select(r => r.Stage));
        Assert.All(fixture.SchemaReads.Skip(3), read => Assert.Same(fixture.Transports[4], read.Transport));
        fixture.AssertReleased(resources: 5, groups: 3);
    }

    [Fact]
    public void Public_group_contains_refuses_overflowing_range_end_without_dispatching_negative_start_or_caching_prefix()
    {
        using var fixture = new RangedRecoveryFixture { Failure = "range-end-overflow" };
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        static PropertyCollection Identity(Guid id, string sid)
        {
            var values = new PropertyCollection(); values.ReplaceLoaded("objectGUID", [id.ToByteArray()]);
            values.ReplaceLoaded("objectSid", [CrossContextSid(sid)]); values.ReplaceLoaded("primaryGroupID", ["513"]); return values;
        }
        static byte[] CrossContextSid(string sid)
        {
            var value = new AdForLinux.Security.Principal.SecurityIdentifier(sid);
            var binary = new byte[value.BinaryLength]; value.GetBinaryForm(binary, 0); return binary;
        }
        fixture.Entry.PropertyReadOverride = (_, _) => Identity(new("417c85f0-2f61-4f82-817c-b119955789f1"), "S-1-5-21-10-20-30-2000");
        using var group = new GroupPrincipal(context, fixture.Entry);
        using var memberEntry = new DirectoryEntry("LDAP://offline.invalid/" + RangedRecoveryFixture.LastDn);
        memberEntry.PropertyReadOverride = (_, _) => Identity(new("a86f1f1d-a559-419d-9730-c09d3cc4cdf4"), "S-1-5-21-10-20-30-1001");
        using var member = new UserPrincipal(context, memberEntry);
        Assert.Throws<OverflowException>(() => group.Members.Contains(member));
        fixture.AssertReleased(1, 3);
        Assert.Equal(new[] { "member;range=0-*" }, fixture.RangesFor(fixture.Transports[0]));
        fixture.Repaired = true;
        Assert.True(group.Members.Contains(member));
        fixture.AssertReleased(2, 7);
        Assert.Equal(new[] { "member;range=0-*", "member;range=2-*" }, fixture.RangesFor(fixture.Transports[1]));
        Assert.True(group.Members.Contains(member));
        fixture.AssertReleased(2, 7); // only the complete repaired lookup can populate the small-group cache
    }
}
