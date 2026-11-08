using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class SharedBudgetClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        internal void Advance(TimeSpan value) => Interlocked.Add(ref ticks, value.Ticks);
    }

    private sealed class BudgetTransport(SharedBudgetFixture fixture, bool measured)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        private readonly Queue<LdapSearchEvent> script = new([
            new LdapSearchEvent.Entry(TransportRow("CN=first,DC=example", new() { ["number"] = ["42"] })),
            new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), fixture.Paged),
            .. fixture.Paged ? new LdapSearchEvent[] {
                new LdapSearchEvent.Entry(TransportRow("CN=second,DC=example", new() { ["number"] = ["43"] })),
                new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false) } : [],
        ]);
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => "directory.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1"))
            {
                Assert.False(measured);
                fixture.RootReads++;
                return new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, new())], [], [], []);
            }
            Assert.True(measured);
            fixture.SchemaReaders.Add(this);
            fixture.SchemaBudgets.Add(command.Timeout);
            fixture.Trace.Add(command.BaseDn == "" ? "schema-root" : "schema-row");
            fixture.Clock.Advance(fixture.SchemaCost);
            var row = command.BaseDn == ""
                ? TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })
                : TransportRow("CN=number,CN=Schema", new() { ["lDAPDisplayName"] = ["number"],
                    ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] });
            return new(ResultCode.Success, "", null, [row], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.CursorTransports.Add(this);
            fixture.OpenBudgets.Add(command.Timeout);
            fixture.Trace.Add("open");
            Assert.Equal(fixture.Paged ? 1 : 0, pageSize);
            Assert.Equal(TimeSpan.FromSeconds(30), command.ServerTimeLimit);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.ReadBudgets.Add(remaining);
            fixture.Trace.Add("read");
            fixture.Clock.Advance(fixture.ReadCost);
            return ValueTask.FromResult(script.Dequeue());
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
        {
            token.ThrowIfCancellationRequested();
            fixture.PageBudgets.Add(remaining);
            fixture.Trace.Add("next-page");
            Assert.Equal(TimeSpan.FromSeconds(30), serverTimeLimit);
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync() { fixture.CursorCloses++; fixture.Trace.Add("cursor-close"); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only budget fixture received a mutation.");
        public void Dispose() { Disposals++; fixture.Trace.Add("resource-close"); }
    }

    private sealed class BudgetGroupOwner(Action release) : IDisposable
    {
        private Action? release = release;
        internal int Disposals;
        public void Dispose() { if (Interlocked.Exchange(ref release, null) is { } action) { Disposals++; action(); } }
    }

    private sealed class SharedBudgetFixture : IDisposable
    {
        internal readonly SharedBudgetClock Clock = new();
        internal readonly DirectoryEntry Root;
        internal readonly DirectorySearcher Searcher;
        internal readonly List<string> Trace = [];
        internal readonly List<TimeSpan> OpenBudgets = [], ReadBudgets = [], PageBudgets = [], SchemaBudgets = [];
        internal readonly List<(int Count, TimeSpan RecipeTimeout)> Admissions = [];
        internal readonly List<BudgetTransport> Transports = [];
        internal readonly List<BudgetTransport> SchemaReaders = [], CursorTransports = [];
        internal readonly List<BudgetGroupOwner> Owners = [];
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BudgetTransport> Pool = new(2, 2, startTimer: false);
        internal TimeSpan AdmissionCost = TimeSpan.FromSeconds(3), ReadCost = TimeSpan.FromSeconds(1), SchemaCost = TimeSpan.FromSeconds(1);
        internal int RootReads, CursorCloses;
        internal readonly bool Paged, Partial, FindOne, Streaming;
        private readonly LdapConnectionProvider.ConnectionKey key;
        private bool measured;

        internal SharedBudgetFixture(string mode)
        {
            FindOne = mode == "FindOne";
            Paged = mode.Contains("paged", StringComparison.Ordinal);
            Partial = mode.StartsWith("async", StringComparison.Ordinal);
            Streaming = Partial || mode == "streaming FindAll";
            Root = RestrictedRecipe().CreateDirectoryEntry("DC=example"); // inert recipe; no cache/bundle access
            key = LdapConnectionProvider.ConnectionKey.Create(Root.BuildOptions(), ReferralChasingOption.None);
            Root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout); // immutable resource recipe, not per-operation deadline
                Assert.Equal(key, LdapConnectionProvider.ConnectionKey.Create(options, referrals));
                Admissions.Add((count, options.Timeout));
                var leases = Pool.AcquireBatch(key, count, () =>
                {
                    var transport = new BudgetTransport(this, measured);
                    Transports.Add(transport);
                    return transport;
                }, reusable: false);
                var owner = new BudgetGroupOwner(() => { foreach (var lease in leases) lease.Dispose(); });
                Owners.Add(owner);
                if (measured) Clock.Advance(AdmissionCost); // elapsed admission, without modifying the recipe/key
                return LdapRestrictedOperation.Wrap(leases.Select(lease => (ILdapRequestTransport)lease.Value).ToArray(), owner, options);
            };
            Root.BindEntry(); // initial object validation is deliberately outside this measured producer budget
            measured = true;
            Searcher = new DirectorySearcher(Root)
            {
                CacheResults = mode != "streaming FindAll",
                Asynchronous = Partial,
                PageSize = Paged ? 1 : 0,
                SizeLimit = Paged ? 2 : 0,
                ServerTimeLimit = TimeSpan.FromSeconds(30),
                ClientTimeout = TimeSpan.FromSeconds(10),
                TimeProvider = Clock,
                ReferralChasing = ReferralChasingOption.None,
            };
        }

        internal void Execute()
        {
            if (FindOne)
                Assert.Equal(42, Assert.IsType<int>(Assert.IsType<SearchResult>(Searcher.FindOne()).Properties["number"][0]));
            else
            {
                using var results = Searcher.FindAll();
                Assert.Equal(Paged ? new[] { 42, 43 } : new[] { 42 },
                    results.Cast<SearchResult>().Select(result => Assert.IsType<int>(result.Properties["number"][0])));
            }
        }
        internal void AssertReleased(int groups, int queries)
        {
            Assert.Equal(groups, Owners.Count);
            Assert.All(Owners, owner => Assert.Equal(1, owner.Disposals));
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(queries, OpenBudgets.Count);
            Assert.Equal(queries, CursorCloses);
            if (queries > 0)
            {
                var queryTransport = Assert.Single(CursorTransports);
                Assert.Equal(2, SchemaReaders.Count);
                Assert.Same(SchemaReaders[0], SchemaReaders[1]);
                if (Streaming || Paged) Assert.NotSame(queryTransport, SchemaReaders[0]);
                else Assert.Same(queryTransport, SchemaReaders[0]);
            }
            Assert.Equal(1, RootReads);
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.All(Admissions, admission => Assert.Equal(TimeSpan.FromSeconds(30), admission.RecipeTimeout));
            Assert.All(Admissions.Skip(1), admission => Assert.Equal(Streaming || Paged ? 2 : 1, admission.Count));
        }
        public void Dispose() { Searcher.Dispose(); Root.Dispose(); Pool.Dispose(); }
    }

    public static IEnumerable<object[]> SharedBudgetModes()
        => new[] { "FindOne", "cached FindAll", "streaming FindAll", "async FindAll", "paged cached FindAll", "async paged FindAll" }
            .Select(mode => new object[] { mode });

    [Theory]
    [MemberData(nameof(SharedBudgetModes))]
    public void Public_neutral_remaining_budget_consumes_partial_admission_cursor_and_schema_work(string mode)
    {
        using var fixture = new SharedBudgetFixture(mode);
        fixture.Execute();

        Assert.Equal(new[] { TimeSpan.FromSeconds(7) }, fixture.OpenBudgets);
        Assert.Equal(fixture.Partial ? new[] { TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(5) }
            : new[] { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(4) }, fixture.SchemaBudgets);
        Assert.Equal(fixture.Paged
            ? fixture.Partial ? new[] { 7, 4, 3, 2 } : new[] { 7, 6, 3, 2 }
            : fixture.Partial ? new[] { 7, 4 } : new[] { 7, 6 }, fixture.ReadBudgets.Select(value => (int)value.TotalSeconds));
        Assert.Equal(fixture.Paged ? new[] { TimeSpan.FromSeconds(3) } : [], fixture.PageBudgets);
        fixture.AssertReleased(groups: 2, queries: 1);
        if (fixture.Paged)
            Assert.True(fixture.Trace.IndexOf("schema-row") < fixture.Trace.IndexOf("next-page"));
        if (!fixture.Streaming && !fixture.Paged)
            Assert.True(fixture.Trace.IndexOf("cursor-close") < fixture.Trace.IndexOf("schema-root"));
    }

    public static IEnumerable<object[]> AdmissionDeadlineBoundaries()
        => SharedBudgetModes().SelectMany(row => new[] { new object[] { row[0], false }, new object[] { row[0], true } });

    [Theory]
    [MemberData(nameof(AdmissionDeadlineBoundaries))]
    public void Admission_completion_before_or_at_deadline_preserves_recipe_releases_group_and_allows_next_operation(string mode, bool expires)
    {
        using var fixture = new SharedBudgetFixture(mode) { AdmissionCost = TimeSpan.FromSeconds(expires ? 10 : 9),
            ReadCost = TimeSpan.Zero, SchemaCost = TimeSpan.Zero };
        if (expires)
        {
            Assert.Throws<TimeoutException>(fixture.Execute);
            fixture.AssertReleased(groups: 2, queries: 0);
            Assert.Empty(fixture.ReadBudgets);
            Assert.Empty(fixture.SchemaBudgets);
            Assert.Empty(fixture.PageBudgets);
            fixture.AdmissionCost = TimeSpan.FromSeconds(9);
        }
        fixture.Execute();
        Assert.Equal(new[] { TimeSpan.FromSeconds(1) }, fixture.OpenBudgets);
        Assert.All(fixture.ReadBudgets, budget => Assert.Equal(TimeSpan.FromSeconds(1), budget));
        Assert.All(fixture.SchemaBudgets, budget => Assert.Equal(TimeSpan.FromSeconds(1), budget));
        Assert.All(fixture.PageBudgets, budget => Assert.Equal(TimeSpan.FromSeconds(1), budget));
        fixture.AssertReleased(groups: expires ? 3 : 2, queries: 1);
        // Deterministic completion-order boundaries, not a claim about an OS
        // scheduling race or about prompt cancellation while admission is held.
    }
}
