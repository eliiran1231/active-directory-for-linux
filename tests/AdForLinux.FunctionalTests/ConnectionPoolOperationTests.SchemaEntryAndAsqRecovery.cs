using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class ClassSchemaFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/CN=item,DC=example");
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<ReadSeamTransport> Transports = [];
        internal readonly List<(ReadSeamTransport Transport, LdapSearchCommand Command)> Requests = [];
        internal readonly string Fault;
        internal bool Repaired;
        internal int PropertyLoads;
        internal ClassSchemaFixture(string fault)
        {
            Fault = fault;
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.UsePropertyCache = false;
            Entry.PropertyReadOverride = (_, _) =>
            {
                PropertyLoads++;
                var values = new PropertyCollection(); values.ReplaceLoaded("objectClass", ["top", "person", "user"]); return values;
            };
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    ReadSeamTransport? transport = null;
                    transport = new ReadSeamTransport(command =>
                    {
                        Requests.Add((transport!, command));
                        if (command.BaseDn == "")
                        {
                            Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, command.Scope);
                            Assert.Equal(new[] { "schemaNamingContext" }, command.Attributes);
                            return Success(TransportRow("", !Repaired && Fault == "missing-root" ? new() :
                                new() { ["schemaNamingContext"] = ["CN=Schema,DC=example"] }));
                        }
                        Assert.Equal("CN=Schema,DC=example", command.BaseDn);
                        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, command.Scope);
                        Assert.Equal("(&(objectClass=classSchema)(lDAPDisplayName=user))", command.Filter);
                        Assert.Equal(new[] { "lDAPDisplayName" }, command.Attributes);
                        if (!Repaired && Fault == "class-code")
                            return new(ResultCode.Unavailable, "", "controlled class-schema failure", [], [], [], []);
                        if (!Repaired && Fault == "no-class") return Success();
                        var user = TransportRow("CN=User,CN=Schema,DC=example", new() { ["lDAPDisplayName"] = ["user"] });
                        return !Repaired && Fault == "ambiguous-class"
                            ? Success(user, TransportRow("CN=SecondUser,CN=Schema,DC=example", new() { ["lDAPDisplayName"] = ["user"] }))
                            : Success(user);
                    });
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        private static LdapSearchResult Success(params LdapTransportEntry[] rows) => new(ResultCode.Success, "", null, rows, [], [], []);
        internal void AssertReleased(int resources, int requests)
        {
            Assert.Equal(resources, Transports.Count); Assert.Equal(requests, Requests.Count);
            Assert.All(Transports, t => Assert.Equal(1, t.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total); Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Entry.Dispose(); Pool.Dispose(); }
    }

    [Theory]
    [InlineData("missing-root")]
    [InlineData("no-class")]
    [InlineData("ambiguous-class")]
    [InlineData("class-code")]
    public void Public_neutral_SchemaEntry_refuses_incomplete_class_discovery_and_retries_without_publishing_or_caching_failure(string fault)
    {
        using var fixture = new ClassSchemaFixture(fault);
        var returned = false;
        var error = Record.Exception(() => { using var failed = fixture.Entry.SchemaEntry; returned = true; });
        if (fault == "class-code") Assert.Equal((int)ResultCode.Unavailable, Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        else Assert.IsType<InvalidOperationException>(error);
        Assert.False(returned);
        var failedRequests = fault == "missing-root" ? 1 : 2;
        fixture.AssertReleased(1, failedRequests);
        Assert.Equal(1, fixture.PropertyLoads);
        Assert.False(fixture.Entry.IsDisposed);
        Assert.All(fixture.Requests, request => Assert.Same(fixture.Transports[0], request.Transport));

        fixture.Repaired = true;
        using var schema = fixture.Entry.SchemaEntry;
        Assert.Equal("LDAP://offline.invalid/CN=User,CN=Schema,DC=example", schema.Path);
        Assert.False(schema.UsePropertyCache);
        _ = schema.Properties; // lazy wrapper/recipe access must not bind or issue another class/property request
        Assert.Equal(1, fixture.PropertyLoads);
        fixture.AssertReleased(2, failedRequests + 2);
        Assert.All(fixture.Requests.Skip(failedRequests), request => Assert.Same(fixture.Transports[1], request.Transport));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_neutral_attribute_scope_query_refuses_Protocols_only_route_without_dispatch_and_recovers_after_clearing_query(bool findOne)
    {
        using var fixture = new DirectoryConversationFixture([new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false)]);
        using var searcher = fixture.Searcher(cached: true, partial: false);
        fixture.Root.BindEntry();
        searcher.AttributeScopeQuery = "member";
        Assert.Throws<PlatformNotSupportedException>(() =>
        {
            if (findOne) _ = searcher.FindOne();
            else { using var refused = searcher.FindAll(); }
        });
        Assert.Equal(2, fixture.Transports.Count); // prebound root and refused ASQ lease
        Assert.All(fixture.Transports, t => Assert.Equal(1, t.Disposals));
        Assert.Equal(0, fixture.Transports.Sum(t => t.Opens));
        Assert.Equal(0, fixture.Transports.Sum(t => t.Reads));
        Assert.Single(fixture.Transports.SelectMany(t => t.BufferedRequests)); // root 1.1 validation only
        Assert.Equal(0, fixture.Pool.Snapshot.Total);

        searcher.AttributeScopeQuery = "";
        if (findOne) Assert.Null(searcher.FindOne());
        else { using var recovered = searcher.FindAll(); Assert.Empty(recovered.Cast<SearchResult>()); }
        fixture.AssertReleased(expectedSessions: 3, expectedReads: 1, expectedPages: 0);
        Assert.Single(fixture.Transports.SelectMany(t => t.BufferedRequests));
        Assert.Equal(new[] { 1, 1, 1 }, fixture.Admissions.Select(a => a.Count));
    }
}
