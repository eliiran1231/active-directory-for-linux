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
    private sealed class IsolatedPublicRow(Guid guid, string description)
    {
        internal readonly Guid Guid = guid;
        internal string Description = description;
    }

    private sealed class PublicSessionIsolation : IDisposable
    {
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool =
            new(perKeyLimit: 2, totalLimit: 2, acquisitionTimeout: TimeSpan.FromSeconds(1), startTimer: false);
        internal readonly List<IsolatedPublicTransport> Transports = [];
        internal readonly List<(IsolatedPublicTransport Transport, LdapSearchCommand Command)> Opened = [];
        internal readonly List<(IsolatedPublicTransport Transport, LdapModifyCommand Command)> Writes = [];
        internal readonly Dictionary<(string Host, string User, string SyntheticSecret, string Dn), IsolatedPublicRow> Rows = [];
        internal readonly Dictionary<string, int> ControlCalls = [];
        internal DirectoryEntry Entry(string host, string dn, string user = "synthetic-reader", string syntheticSecret = "fixture-only-A")
        {
            var entry = new DirectoryEntry($"LDAP://{host}:636/{dn}", user, syntheticSecret, AuthenticationTypes.SecureSocketsLayer);
            entry.Options.Referral = ReferralChasingOption.None;
            entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                while (Pool.NewGeneration() < minimum) { } // honor provider freshness floors in this isolated pool
                return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new IsolatedPublicTransport(this, options.Clone());
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: LdapConnectionProvider.CanReuse(options, referrals), preferFresh: fresh,
                    minimumGeneration: minimum).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            };
            return entry;
        }
        internal IsolatedPublicRow Row(string host, string user, string secret, string dn)
            => Rows[(host, user, secret, dn)];
        internal void AssertIdle(int resources)
        {
            Assert.Equal(resources, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
            // A complete new batch can borrow every retained resource without
            // creating anything: no facade is still holding an exclusive lease.
            foreach (var group in Transports.Where(t => t.Disposals == 0).GroupBy(t =>
                         LdapConnectionProvider.ConnectionKey.Create(t.Recipe, ReferralChasingOption.None)))
            {
                var leases = Pool.AcquireBatch(group.Key, group.Count(), () => throw new InvalidOperationException("Operation retained a session."));
                foreach (var lease in leases) lease.Dispose();
            }
        }
        internal void DisposeAndAssert() { Pool.Dispose(); Assert.All(Transports, t => Assert.Equal(1, t.Disposals)); }
        public void Dispose() => Pool.Dispose();
    }

    private sealed class IsolatedPublicTransport(PublicSessionIsolation fixture, LdapConnectionOptions recipe)
        : ILdapConversationTransport, ILdapSearchCursor, ILdapMutationTransport, IDisposable
    {
        internal readonly LdapConnectionOptions Recipe = recipe;
        internal int Disposals, SchemaRoots, SchemaQueries, CursorReads, CursorCloses;
        private byte returnedCookie;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.Modify;
        public TimeSpan Timeout => Recipe.Timeout;
        public string? ConnectedHost => Recipe.Host;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command.Attributes.Contains("1.1")) return Success(TransportRow(command.BaseDn, new()));
            if (command.BaseDn == "")
            {
                SchemaRoots++;
                return Success(TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] }));
            }
            if (command.BaseDn == "CN=Schema")
            {
                SchemaQueries++;
                return Success(TransportRow("CN=extensionValue,CN=Schema", new() {
                    ["lDAPDisplayName"] = ["extensionValue"], ["attributeSyntax"] = [Recipe.Host == "beta.invalid" ? "2.5.5.12" : "2.5.5.9"],
                    ["oMSyntax"] = [Recipe.Host == "beta.invalid" ? "64" : "2"] }));
            }
            var row = fixture.Row(Recipe.Host, Recipe.BindDn!, Recipe.BindPassword!, command.BaseDn);
            return Success(TransportRow(command.BaseDn, new() { ["objectGUID"] = [row.Guid.ToByteArray()],
                ["description"] = [row.Description], ["extensionValue"] = ["42"] }));
        }
        private static LdapSearchResult Success(params LdapTransportEntry[] rows) => new(ResultCode.Success, "", null, rows, [], [], []);
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, pageSize);
            fixture.Opened.Add((this, command));
            var body = ControlBody(command, "1.2.840.113556.1.4.841");
            var flags = (int)body.ReadInteger(); _ = body.ReadInteger();
            var cookie = body.ReadOctetString(); body.ThrowIfNotEmpty();
            var a = command.Filter == "(description=A)";
            Assert.Contains(command.Filter, new[] { "(description=A)", "(description=B)" });
            Assert.Equal(a ? 1 : 2048, flags);
            var calls = fixture.ControlCalls.GetValueOrDefault(command.Filter);
            Assert.InRange(calls, 0, 1);
            Assert.Equal(new byte[] { a ? (byte)(calls == 0 ? 11 : 31) : (byte)(calls == 0 ? 22 : 42) }, cookie);
            returnedCookie = a ? (byte)(calls == 0 ? 31 : 33) : (byte)(calls == 0 ? 42 : 44);
            fixture.ControlCalls[command.Filter] = calls + 1;
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); CursorReads++;
            var writer = new AsnWriter(AsnEncodingRules.BER);
            writer.PushSequence(); writer.WriteInteger(0); writer.WriteInteger(0); writer.WriteOctetString([returnedCookie]); writer.PopSequence();
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success, "", null, [],
                [new("1.2.840.113556.1.4.841", writer.Encode(), false)]), false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Control isolation query advanced a page.");
        public ValueTask DisposeAsync() { CursorCloses++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); submission.BeforeSend();
            var modify = Assert.IsType<LdapModifyCommand>(command);
            fixture.Writes.Add((this, modify));
            var change = Assert.Single(modify.Changes);
            Assert.Equal("description", change.Name); Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
            fixture.Row(Recipe.Host, Recipe.BindDn!, Recipe.BindPassword!, modify.DistinguishedName).Description = Encoding.UTF8.GetString(Assert.Single(change.Values));
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => MutateAsync(command, submission, token);
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData("same")]
    [InlineData("identity")]
    [InlineData("credential")]
    [InlineData("endpoint")]
    public void Independent_public_searchers_keep_credentials_and_cookies_isolated_across_compatible_resource_reuse(string difference)
    {
        using var fixture = new PublicSessionIsolation();
        var hostB = difference == "endpoint" ? "beta.invalid" : "alpha.invalid";
        var userB = difference == "identity" ? "synthetic-other-reader" : "synthetic-reader";
        var secretB = difference == "credential" ? "fixture-only-B" : "fixture-only-A";
        using var rootA = fixture.Entry("alpha.invalid", "DC=example");
        using var rootB = fixture.Entry(hostB, "DC=example", userB, secretB);
        rootA.BindEntry(); rootB.BindEntry(); // finish object validation before testing query reuse
        var syncA = new DirectorySynchronization([11]) { Option = DirectorySynchronizationOptions.ObjectSecurity };
        var syncB = new DirectorySynchronization([22]) { Option = DirectorySynchronizationOptions.ParentsFirst };
        using var a = new DirectorySearcher(rootA, "(description=A)") { DirectorySynchronization = syncA, ReferralChasing = ReferralChasingOption.None };
        using var b = new DirectorySearcher(rootB, "(description=B)") { DirectorySynchronization = syncB, ReferralChasing = ReferralChasingOption.None };
        using (var results = a.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(new byte[] { 31 }, syncA.GetDirectorySynchronizationCookie());
        Assert.Equal(new byte[] { 22 }, syncB.GetDirectorySynchronizationCookie());
        using (var results = b.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(new byte[] { 31 }, syncA.GetDirectorySynchronizationCookie());
        Assert.Equal(new byte[] { 42 }, syncB.GetDirectorySynchronizationCookie());
        using (var results = a.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        using (var results = b.FindAll()) Assert.Empty(results.Cast<SearchResult>());
        Assert.Equal(new byte[] { 33 }, syncA.GetDirectorySynchronizationCookie());
        Assert.Equal(new byte[] { 44 }, syncB.GetDirectorySynchronizationCookie());
        Assert.Equal(4, fixture.Opened.Count);
        Assert.Same(fixture.Opened[0].Transport, fixture.Opened[2].Transport);
        Assert.Same(fixture.Opened[1].Transport, fixture.Opened[3].Transport);
        if (difference == "same") Assert.Same(fixture.Opened[0].Transport, fixture.Opened[1].Transport);
        else Assert.NotSame(fixture.Opened[0].Transport, fixture.Opened[1].Transport);
        foreach (var index in new[] { 0, 2 })
        {
            Assert.Equal("alpha.invalid", fixture.Opened[index].Transport.Recipe.Host);
            Assert.Equal("synthetic-reader", fixture.Opened[index].Transport.Recipe.BindDn);
            Assert.Equal("fixture-only-A", fixture.Opened[index].Transport.Recipe.BindPassword);
        }
        foreach (var index in new[] { 1, 3 })
        {
            Assert.Equal(hostB, fixture.Opened[index].Transport.Recipe.Host);
            Assert.Equal(userB, fixture.Opened[index].Transport.Recipe.BindDn);
            Assert.Equal(secretB, fixture.Opened[index].Transport.Recipe.BindPassword);
        }
        foreach (var (index, cookie) in new[] { (0, (byte)11), (1, (byte)22), (2, (byte)31), (3, (byte)42) })
        {
            var saved = ControlBody(fixture.Opened[index].Command, "1.2.840.113556.1.4.841");
            Assert.Equal(index % 2 == 0 ? 1 : 2048, (int)saved.ReadInteger()); _ = saved.ReadInteger();
            Assert.Equal(new[] { cookie }, saved.ReadOctetString()); saved.ThrowIfNotEmpty();
        }
        Assert.Equal(4, fixture.Transports.Sum(t => t.CursorReads));
        Assert.Equal(4, fixture.Transports.Sum(t => t.CursorCloses));
        fixture.AssertIdle(difference == "same" ? 1 : 2);
        fixture.DisposeAndAssert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Independent_public_entries_keep_identity_values_pending_edits_and_endpoint_schema_results_separate(bool sameEndpoint)
    {
        using var fixture = new PublicSessionIsolation();
        var hostB = sameEndpoint ? "alpha.invalid" : "beta.invalid";
        const string one = "CN=one,DC=example", two = "CN=two,DC=example";
        var rowA = new IsolatedPublicRow(new("077e1258-4237-4731-ad7e-069fc175f57a"), "alpha first");
        var rowB = new IsolatedPublicRow(new("79f011b0-857e-472f-bf12-5d914829d4f7"), "beta second");
        fixture.Rows.Add(("alpha.invalid", "synthetic-reader", "fixture-only-A", one), rowA);
        fixture.Rows.Add((hostB, "synthetic-reader", "fixture-only-A", two), rowB);
        using var a = fixture.Entry("alpha.invalid", one);
        using var b = fixture.Entry(hostB, two);
        string[] names = ["description", "objectGUID", "extensionValue"];
        a.RefreshCache(names); b.RefreshCache(names);
        Assert.Equal(rowA.Guid, a.Guid); Assert.Equal(rowB.Guid, b.Guid);
        Assert.Equal(42, Assert.IsType<int>(a.Properties["extensionValue"].Value));
        if (sameEndpoint) Assert.Equal(42, Assert.IsType<int>(b.Properties["extensionValue"].Value));
        else Assert.Equal("42", Assert.IsType<string>(b.Properties["extensionValue"].Value));
        var pending = a.Properties["description"];
        pending.Value = "only A pending";
        rowB.Description = "external B";
        b.RefreshCache(names);
        Assert.True(pending.Changed); Assert.Equal("only A pending", pending.Value);
        Assert.Equal("external B", b.Properties["description"].Value);
        Assert.Equal(rowA.Guid, a.Guid); Assert.Equal(rowB.Guid, b.Guid);
        a.CommitChanges();
        var write = Assert.Single(fixture.Writes);
        Assert.Equal("alpha.invalid", write.Transport.Recipe.Host);
        Assert.Equal(one, write.Command.DistinguishedName);
        Assert.Equal(Encoding.UTF8.GetBytes("only A pending"), Assert.Single(Assert.Single(write.Command.Changes).Values));
        Assert.Equal("only A pending", rowA.Description); Assert.Equal("external B", rowB.Description);
        a.RefreshCache(names);
        Assert.Equal("only A pending", a.Properties["description"].Value);
        Assert.Equal("external B", b.Properties["description"].Value);
        Assert.Equal(42, Assert.IsType<int>(a.Properties["extensionValue"].Value));
        if (!sameEndpoint) Assert.Equal("42", Assert.IsType<string>(b.Properties["extensionValue"].Value));
        Assert.Equal(sameEndpoint ? 1 : 2, fixture.Transports.Count);
        Assert.All(fixture.Transports, t => { Assert.Equal(1, t.SchemaRoots); Assert.Equal(1, t.SchemaQueries); });
        fixture.AssertIdle(sameEndpoint ? 1 : 2);
        fixture.DisposeAndAssert();
    }
}
