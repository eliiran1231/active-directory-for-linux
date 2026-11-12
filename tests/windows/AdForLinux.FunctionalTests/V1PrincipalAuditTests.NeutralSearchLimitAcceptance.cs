using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class NeutralLimitFixture : IDisposable
    {
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly List<NeutralLimitTransport> Transports = [];
        internal readonly List<LdapSearchCommand> Queries = [];
        internal readonly InvalidOperationException Failure = new("controlled neutral schema failure");
        internal string Stage;
        internal bool Partial;
        internal DirectorySearcher Native = null!;
        internal int RootReads, CursorCloses, SchemaReads;
        internal NeutralLimitFixture(string stage, bool partial)
        {
            Stage = stage; Partial = partial;
            Context.SearchRoot.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new NeutralLimitTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        internal void AssertReleased(int resources, int cursors)
        {
            Assert.Equal(1, RootReads);
            Assert.Equal(resources, Transports.Count);
            Assert.All(Transports, value => Assert.Equal(1, value.Disposals));
            Assert.Equal(cursors, CursorCloses);
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Context.Dispose(); Pool.Dispose(); }
    }

    private sealed class NeutralLimitTransport(NeutralLimitFixture fixture) : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private int position;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(30);
        public string? ConnectedHost => "offline.invalid";
        private static LdapTransportEntry Row(string dn, params (string Name, string Value)[] attributes)
            => new(dn, attributes.ToDictionary(value => value.Name, value => new[] { Encoding.UTF8.GetBytes(value.Value) }, StringComparer.OrdinalIgnoreCase), []);
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1"))
            {
                fixture.RootReads++;
                return new(ResultCode.Success, "", null, [Row(command.BaseDn)], [], [], []);
            }
            Assert.Equal(7, fixture.Native.SizeLimit);
            fixture.SchemaReads++;
            if (fixture.Stage == "schema") throw fixture.Failure;
            return command.BaseDn.Length == 0
                ? new(ResultCode.Success, "", null, [Row("", ("schemaNamingContext", "CN=Schema,DC=example,DC=test"))], [], [], [])
                : new(ResultCode.Success, "", null, [Row("CN=customInteger," + command.BaseDn,
                    ("lDAPDisplayName", "customInteger"), ("attributeSyntax", "2.5.5.9"), ("oMSyntax", "2"))], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, pageSize);
            fixture.Queries.Add(command);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (position++ == 0 && fixture.Stage is not ("query" or "empty"))
                return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.Entry(Row("CN=found,DC=example,DC=test", ("customInteger", "bad-integer"))));
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(
                fixture.Stage == "query" ? ResultCode.NoSuchObject : fixture.Partial ? ResultCode.SizeLimitExceeded : ResultCode.Success,
                "", null, [], []), false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Unpaged fixture advanced a page.");
        public ValueTask DisposeAsync() { fixture.CursorCloses++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Search fixture attempted a mutation.");
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData("query", false)]
    [InlineData("empty", false)]
    [InlineData("schema", false)]
    [InlineData("conversion", false)]
    [InlineData("schema", true)]
    [InlineData("conversion", true)]
    public void Neutral_FindOne_limit_distinguishes_query_failure_from_accepted_rows(string stage, bool partial)
    {
        using var fixture = new NeutralLimitFixture(stage, partial);
        using var query = new UserPrincipal(fixture.Context);
        using var principals = new PrincipalSearcher(query);
        fixture.Native = Assert.IsType<DirectorySearcher>(principals.GetUnderlyingSearcher());
        fixture.Native.PageSize = 0;
        fixture.Native.ReferralChasing = ReferralChasingOption.None;
        fixture.Native.SizeLimit = 7;

        var error = Record.Exception(() => Assert.Null(principals.FindOne()));
        if (stage == "query") Assert.IsType<PrincipalOperationException>(error);
        else if (stage == "schema") Assert.Same(fixture.Failure, error);
        else if (stage == "conversion") Assert.IsType<FormatException>(error);
        else Assert.Null(error);
        Assert.Equal(stage == "query" ? 1 : 7, fixture.Native.SizeLimit);
        Assert.Equal(1, Assert.Single(fixture.Queries).SizeLimit);
        Assert.Equal(stage == "schema" ? 1 : stage == "conversion" ? 2 : 0, fixture.SchemaReads);
        fixture.AssertReleased(2, 1);

        fixture.Stage = "empty";
        fixture.Partial = false;
        fixture.Native.SizeLimit = 7;
        using var recovered = principals.FindAll();
        Assert.Empty(recovered);
        Assert.Equal(new[] { 1, 7 }, fixture.Queries.Select(command => command.SizeLimit));
        fixture.AssertReleased(3, 2);
    }
}
