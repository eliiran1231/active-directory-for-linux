using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    // Every request is handled by an uninitialized recording connection.
    // No LDAP connection, bind or network dispatch is performed. The baseline
    // probe adapts only the pre-PR pool resource type, retaining this behavior.
    private sealed class ProtocolFailureScopeFixture : IDisposable
    {
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        internal readonly List<SearchRequest> Queries = [];
        internal readonly List<int> Closes = [];
        internal Func<int, SearchResponse> Reply = _ => EmptyProtocolScopeResponse();
        internal int RootReads;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal ProtocolFailureScopeFixture()
        {
            var root = Context.SearchRoot;
            root.Options.Referral = ReferralChasingOption.None;
            root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var index = Closes.Count;
                    Closes.Add(0);
                    var connection = SaveReadConnection.Create(request =>
                    {
                        var search = Assert.IsType<SearchRequest>(request);
                        if (search.Attributes.Contains("1.1"))
                        {
                            RootReads++;
                            return SaveResponse(search.DistinguishedName, [], 1, ResultCode.Success, false, false);
                        }
                        Queries.Add(search);
                        return Reply(Queries.Count);
                    }, () => Closes[index]++);
                    return new BoundLdapSession(connection, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        internal void AssertReleased()
        {
            Assert.Equal(1, RootReads);
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.All(Closes, count => Assert.Equal(1, count));
        }
        public void Dispose() { Context.Dispose(); Pool.Dispose(); }
    }

    private static SearchResponse EmptyProtocolScopeResponse(params DirectoryControl[] controls)
        => (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), BindingFlags.Instance | BindingFlags.NonPublic,
            null, new object?[] { null, controls, ResultCode.Success, null, Array.Empty<Uri>() }, null)!;

    private static void AssertFindOneFailureDoesNotChangeFollowingSearches()
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principalSearcher = new PrincipalSearcher(query);
        var searcher = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        searcher.PageSize = 0;
        searcher.ReferralChasing = ReferralChasingOption.None;
        searcher.ConfigureConnectionOverride = _ => { }; // fake Protocols connection has no native session options
        searcher.SizeLimit = 37;
        var failure = new DirectoryOperationException(SaveResponse("", [], 0, ResultCode.Unavailable, false, false),
            "controlled LDAP unavailable");
        fixture.Reply = number => number == 1 ? throw failure : EmptyProtocolScopeResponse();

        var error = Assert.Throws<PrincipalServerDownException>(() => principalSearcher.FindOne());
        Assert.Same(failure, Assert.IsType<DirectoryServicesCOMException>(error.InnerException).InnerException);
        var limitAfterFailure = searcher.SizeLimit;
        using (var results = principalSearcher.FindAll()) Assert.Empty(results);
        // A caller can explicitly restore configuration; this does not prove
        // row loss at a server, but exposes the exact follow-on request limit.
        searcher.SizeLimit = 37;
        using (var results = principalSearcher.FindAll()) Assert.Empty(results);
        fixture.AssertReleased();
        Assert.Equal(37, searcher.SizeLimit);
        Assert.Equal(new[] { 1, 37, 37 }, fixture.Queries.Select(request => request.SizeLimit));
        Assert.Equal(37, limitAfterFailure);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(37)]
    public void Empty_FindOne_restores_caller_limit_before_following_FindAll(int originalLimit)
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principalSearcher = new PrincipalSearcher(query);
        var searcher = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        searcher.PageSize = 0;
        searcher.ReferralChasing = ReferralChasingOption.None;
        searcher.ConfigureConnectionOverride = _ => { };
        searcher.SizeLimit = originalLimit;

        Assert.Null(principalSearcher.FindOne());
        Assert.Equal(originalLimit, searcher.SizeLimit);
        using (var results = principalSearcher.FindAll()) Assert.Empty(results);
        Assert.Equal(new[] { 1, originalLimit }, fixture.Queries.Select(request => request.SizeLimit));
        fixture.AssertReleased();
    }

}
