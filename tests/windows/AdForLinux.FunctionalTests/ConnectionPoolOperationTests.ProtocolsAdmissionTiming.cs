using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData("FindOne")]
    [InlineData("cached FindAll")]
    [InlineData("streaming FindAll")]
    public async Task Protocols_client_response_timeout_starts_after_pool_admission_characterization(string operation)
    {
        using var cleanup = new CancellationTokenSource();
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2,
            acquisitionTimeout: TimeSpan.FromSeconds(5), startTimer: false);
        using var root = new Entry("LDAP://offline.invalid/DC=example,DC=test");
        root.Options.Referral = ReferralChasingOption.None;
        var connections = new List<Connection>();
        var responseTimeout = TimeSpan.FromMilliseconds(100);
        var rootReads = 0;
        var querySends = 0;
        var begins = 0;
        var configured = 0;
        var sentinel = new InvalidOperationException("controlled asynchronous initiation; no native request");
        BoundLdapSession Create(LdapConnectionOptions options, ReferralChasingOption referrals)
        {
            Connection? connection = null;
            connection = Connection.Create(request =>
            {
                var search = Assert.IsType<SearchRequest>(request);
                Assert.Equal("DC=example,DC=test", search.DistinguishedName);
                if (search.Attributes.Contains("1.1"))
                {
                    rootReads++;
                    return Response(search.DistinguishedName, new());
                }
                querySends++;
                Assert.Equal(responseTimeout, connection!.Timeout);
                Assert.Equal(operation == "FindOne" ? 1 : 0, search.SizeLimit);
                const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
                return (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
                    new object?[] { null, Array.Empty<DirectoryControl>(), ResultCode.Success, null, Array.Empty<Uri>() }, null)!;
            });
            connections.Add(connection);
            return new BoundLdapSession(connection, options, new(options), referrals);
        }
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count,
                () => Create(options, referrals), cleanup.Token, reusable: false)
                .Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();

        root.BindEntry();
        var options = root.BuildOptions();
        var held = pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None), 2,
            () => Create(options, ReferralChasingOption.None), reusable: false);
        using var searcher = new Searcher(root)
        {
            ClientTimeout = responseTimeout,
            CacheResults = operation != "streaming FindAll",
            ReferralChasing = ReferralChasingOption.None,
        };
        searcher.ConfigureConnectionOverride = connection =>
        {
            Assert.Contains(connection, connections);
            configured++;
        };
        searcher.BeginSearchOverride = (connection, request, timeout, partial) =>
        {
            Assert.Contains(connection, connections);
            Assert.Equal(responseTimeout, timeout);
            Assert.Equal(PartialResultProcessing.NoPartialResultSupport, partial);
            begins++;
            throw sentinel; // BeginSendRequest is nonvirtual; never call it here.
        };
        var pending = Task.Factory.StartNew(() => Record.Exception(() =>
        {
            if (operation == "FindOne") Assert.Null(searcher.FindOne());
            else { using var results = searcher.FindAll(); Assert.Empty(results.Cast<SearchResult>()); }
        }), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        var observedPending = false;
        var elapsed = TimeSpan.Zero;
        Exception? failure = null;
        try
        {
            Assert.True(SpinWait.SpinUntil(() => pool.Snapshot.Waiting == 1, TimeSpan.FromSeconds(2)),
                "The synthetic query did not enter the held pool wait.");
            var observation = System.Diagnostics.Stopwatch.StartNew();
            observedPending = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromMilliseconds(300))) != pending;
            elapsed = observation.Elapsed;
            Assert.Equal(0, querySends);
            Assert.Equal(0, begins);
        }
        finally
        {
            foreach (var lease in held) lease.Dispose();
            try { failure = await pending.WaitAsync(TimeSpan.FromSeconds(2)); }
            catch (TimeoutException)
            {
                cleanup.Cancel();
                failure = await pending.WaitAsync(TimeSpan.FromSeconds(2));
            }
        }

        Assert.True(observedPending, "ClientTimeout is a response timeout on Protocols; admission has a separate budget.");
        Assert.True(elapsed >= TimeSpan.FromMilliseconds(250));
        if (operation == "streaming FindAll") Assert.Same(sentinel, failure);
        else Assert.Null(failure);
        Assert.Equal(1, rootReads);
        Assert.Equal(operation == "streaming FindAll" ? 0 : 1, querySends);
        Assert.Equal(operation == "streaming FindAll" ? 1 : 0, begins);
        Assert.Equal(1, configured);
        Assert.Equal(operation == "streaming FindAll" ? 5 : 4, connections.Count);
        Assert.All(connections, connection => Assert.Equal(1, connection.Disposals));
        Assert.Equal(0, pool.Snapshot.Total);
        Assert.Equal(0, pool.Snapshot.Waiting);
        // Characterizes existing response-timeout scope. A late synthetic send
        // is expected here; this asserts no new total-operation deadline.
    }
}
