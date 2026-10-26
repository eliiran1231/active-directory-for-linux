using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData(false, ResultCode.Success)]
    [InlineData(true, ResultCode.Success)]
    [InlineData(false, ResultCode.UnwillingToPerform)]
    [InlineData(true, ResultCode.UnwillingToPerform)]
    public void Buffered_public_search_drains_terminal_before_schema_on_single_capacity(bool findOne, ResultCode code)
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
        var trace = new List<string>();
        ConversationTransport? query = null;
        var created = 0;
        using var root = new Entry("LDAP://directory.invalid/DC=example", null, null, AuthenticationTypes.Secure);
        root.Options.Referral = ReferralChasingOption.None;
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
            {
                var transport = new ConversationTransport(trace);
                if (++created == 2)
                {
                    query = transport;
                    transport.Events = new([new LdapSearchEvent.Entry(TransportRow("CN=first", new() { ["cn"] = ["first"] }))]);
                    if (!findOne) transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true));
                    transport.Events.Enqueue(new LdapSearchEvent.Entry(TransportRow("CN=first", new() { ["sn"] = ["second"] })));
                    transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(code), false));
                }
                return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
            }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        using var searcher = new Searcher(root) { ReferralChasing = ReferralChasingOption.None, PageSize = 2 };
        var error = Record.Exception(() =>
        {
            if (findOne) Assert.NotNull(searcher.FindOne());
            else { using var result = searcher.FindAll(); Assert.Equal(2, result.Count); }
        });
        Assert.NotNull(query);
        Assert.Equal(findOne ? 3 : 4, query.Reads);
        Assert.Equal(findOne ? 0 : 1, query.Pages);
        Assert.Equal(2, created);
        Assert.Equal(2, trace.Count(value => value == "session-close"));
        if (code == ResultCode.Success)
        {
            Assert.Null(error);
            if (findOne) Assert.Equal(2, trace.Count(value => value == "buffered-search")); // ignored second row needs no schema
            Assert.True(trace.LastIndexOf("buffered-search") > trace.IndexOf("cursor-close"));
            Assert.True(trace.LastIndexOf("session-close") > trace.LastIndexOf("buffered-search"));
        }
        else
        {
            Assert.IsType<DirectoryServicesCOMException>(error);
            Assert.Equal(1, trace.Count(value => value == "buffered-search")); // only initial object lookup
        }
    }

    [Fact]
    public void Neutral_request_mapping_rejects_unrepresented_policy_before_dispatch()
    {
        using var transport = new ConversationTransport([]);
        var request = new SearchRequest("DC=example", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Subtree, "cn");
        request.Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Always;
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.FromRequest(transport, request, transport.Timeout));
        request.Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Never;
        request.TimeLimit = TimeSpan.FromSeconds(1);
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.FromRequest(transport, request, transport.Timeout));
        request.TimeLimit = TimeSpan.Zero;
        request.Controls.Add(new DirectoryControl("1.2.3", [], false, false));
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.FromRequest(transport, request, transport.Timeout));
        Assert.Equal(TimeSpan.Zero, transport.OpenBudget);
    }

    [Theory]
    [InlineData(false, ResultCode.Success, 1)]
    [InlineData(true, ResultCode.Success, 1)]
    [InlineData(false, ResultCode.SizeLimitExceeded, 1)]
    [InlineData(false, ResultCode.UnwillingToPerform, 0)]
    [InlineData(true, ResultCode.UnwillingToPerform, 1)]
    public void Public_streaming_facade_preserves_partial_result_policy_and_releases_pair(bool partial, ResultCode result, int expected)
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        var trace = new List<string>();
        var transport = new ConversationTransport(trace);
        transport.Events = new([new LdapSearchEvent.Entry(TransportRow("CN=first", new() { ["cn"] = ["first"] })),
            new LdapSearchEvent.PageEnd(Envelope(result), false)]);
        using var root = new Entry("LDAP://directory.invalid/DC=example", null, null, AuthenticationTypes.Secure);
        root.Options.Referral = ReferralChasingOption.None;
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count,
                () => new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals),
                reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        using var searcher = new Searcher(root) { CacheResults = false, Asynchronous = partial, ReferralChasing = ReferralChasingOption.None };
        using var results = searcher.FindAll();
        var found = new List<SearchResult>();
        var error = Record.Exception(() => { foreach (SearchResult entry in results) found.Add(entry); });
        Assert.Equal(expected, found.Count);
        if (result == ResultCode.UnwillingToPerform) Assert.IsType<DirectoryServicesCOMException>(error);
        else Assert.Null(error);
        Assert.Equal(3, trace.Count(value => value == "session-close"));
        Assert.True(trace.IndexOf("cursor-close") < trace.LastIndexOf("session-close"));
    }
}
