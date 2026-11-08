using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class PrincipalReadFixture : IDisposable
    {
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(2, 2, startTimer: false);
        internal readonly List<SearchRequest> Reads = [];
        internal readonly List<DirectoryRequest> Writes = [];
        internal ResultCode MutationResult = ResultCode.Success;
        internal bool LoseMutationResponse;
        internal readonly Guid Identity = new("d1b69f09-34f0-48fa-9417-f0c61173508e");

        internal PrincipalReadFixture()
        {
            Context.SearchRoot.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var connection = SaveReadConnection.Create(request =>
                    {
                        if (request is DeleteRequest or ModifyDNRequest)
                        {
                            Writes.Add(request);
                            if (LoseMutationResponse) throw new TimeoutException("controlled mutation response loss");
                            var response = SaveResponse("", [], 0, MutationResult, false, false);
                            // Protocols throws for definitive LDAP failures.
                            if (MutationResult != ResultCode.Success) throw new DirectoryOperationException(response);
                            return response;
                        }
                        var search = Assert.IsType<SearchRequest>(request);
                        Reads.Add(search);
                        if (search.DistinguishedName == "")
                            return SaveResponse("", [], 0, ResultCode.Success, false, false);
                        var dn = search.Attributes.Contains("1.1") ? search.DistinguishedName : "CN=found,DC=example,DC=test";
                        return SaveResponse(dn, new()
                        {
                            ["objectGUID"] = [Identity.ToByteArray()],
                            ["objectSid"] = [SecurityDescriptorFixtures.U1],
                            ["objectClass"] = ["top", "person", "user"],
                            ["sAMAccountName"] = ["found-account"],
                            ["description"] = ["found description"],
                        }, 1, ResultCode.Success, false, false);
                    }, () => { });
                    return new BoundLdapSession(connection, options, new LdapAuthenticationSource(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        internal PrincipalSearcher Search(Principal query)
        {
            var principalSearcher = new PrincipalSearcher(query);
            var searcher = (DirectorySearcher)principalSearcher.GetUnderlyingSearcher();
            searcher.PageSize = 0;
            searcher.ReferralChasing = ReferralChasingOption.None;
            searcher.ConfigureConnectionOverride = _ => { };
            return principalSearcher;
        }

        public void Dispose() { Context.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData(typeof(UserPrincipal))]
    [InlineData(typeof(GroupPrincipal))]
    [InlineData(typeof(ComputerPrincipal))]
    public void Public_FindOne_materializes_typed_principal_through_controlled_request_pipeline(Type type)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = (Principal)Activator.CreateInstance(type, fixture.Context)!;
        query.SamAccountName = "found-account";
        using var searcher = fixture.Search(query);
        var underlying = (DirectorySearcher)searcher.GetUnderlyingSearcher();
        underlying.SizeLimit = 19;

        using var principal = Assert.IsAssignableFrom<Principal>(searcher.FindOne());
        Assert.Equal(type, principal.GetType());
        Assert.Equal(fixture.Identity, principal.Guid);
        Assert.Equal("CN=found,DC=example,DC=test", principal.DistinguishedName);
        Assert.Equal("found-account", principal.SamAccountName);
        Assert.Equal("found description", principal.Description);
        Assert.Same(fixture.Context, principal.Context);
        Assert.Equal(19, underlying.SizeLimit);
        var queryRequest = Assert.Single(fixture.Reads, request => request.Scope == System.DirectoryServices.Protocols.SearchScope.Subtree);
        Assert.Equal(1, queryRequest.SizeLimit);
        Assert.Contains("(sAMAccountName=found-account)", Assert.IsType<string>(queryRequest.Filter));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_FindAll_defers_principal_entry_reads_and_obeys_context_lifetime(bool disposeContext)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var searcher = fixture.Search(query);
        using var results = searcher.FindAll();
        // Search reads projected rows; opening a full principal remains deferred.
        Assert.DoesNotContain(fixture.Reads, request => request.DistinguishedName == "CN=found,DC=example,DC=test");
        var readsBeforeCurrent = fixture.Reads.Count;
        using var cursor = results.GetEnumerator();
        Assert.True(cursor.MoveNext());
        Assert.Equal(readsBeforeCurrent, fixture.Reads.Count);

        if (disposeContext)
        {
            fixture.Context.Dispose();
            Assert.Throws<ObjectDisposedException>(() => _ = cursor.Current);
            Assert.Equal(readsBeforeCurrent, fixture.Reads.Count);
        }
        else
        {
            using var principal = cursor.Current;
            Assert.Equal(fixture.Identity, principal.Guid);
            Assert.Equal("found description", principal.Description);
            Assert.Contains(fixture.Reads, request => request.DistinguishedName == "CN=found,DC=example,DC=test");
            Assert.False(cursor.MoveNext());
        }
    }
}
