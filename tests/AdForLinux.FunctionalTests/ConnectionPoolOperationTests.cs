using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Runtime.CompilerServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class Connection : LdapConnection
    {
        private Connection() : base("offline.invalid") { }
        internal Func<DirectoryRequest, DirectoryResponse> Send = null!;
        internal int Disposals;
        internal static Connection Create(Func<DirectoryRequest, DirectoryResponse> send)
        {
            var value = (Connection)RuntimeHelpers.GetUninitializedObject(typeof(Connection));
            value.Send = send; value.Timeout = TimeSpan.FromSeconds(30); return value;
        }
        public override DirectoryResponse SendRequest(DirectoryRequest request) => Send(request);
        protected override void Dispose(bool disposing) { if (disposing) Disposals++; }
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool;
        internal readonly List<Connection> Connections = [];
        internal readonly List<DirectoryRequest> Requests = [];
        internal Exception? Failure;
        internal Action<DirectoryRequest>? OnRequest;
        internal Fixture(int capacity = 1) => Pool = new(capacity, capacity, startTimer: false,
            acquisitionTimeout: TimeSpan.FromMilliseconds(100));
        internal Entry Entry(string name = "first", bool defaultReferrals = false, AuthType authentication = AuthType.Basic, bool ambient = false)
        {
            var entry = new Entry("LDAP://directory.invalid/CN=" + name,
                new LdapConnectionOptions { Host = "directory.invalid", BindDn = ambient ? null : "reader", BindPassword = ambient ? null : "test password", AuthenticationType = authentication });
            entry.OperationSessionFactory = Open;
            if (!defaultReferrals) entry.Options.Referral = ReferralChasingOption.None;
            return entry;
        }
        private LdapConnectionProvider.Session[] Open(LdapConnectionOptions options, int count,
            ReferralChasingOption referrals, bool fresh, long minimum)
        {
            // Entry generation stamps come from the process provider. Advance this
            // isolated fake pool's sequence to the same admission threshold.
            while (Pool.NewGeneration() < minimum) { }
            var authentication = new LdapAuthenticationSource(options);
            return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
            {
                var connection = Connection.Create(request =>
                {
                    Requests.Add(request);
                    OnRequest?.Invoke(request);
                    if (Failure is { } failure) throw failure;
                    var search = Assert.IsType<SearchRequest>(request);
                    return Response(search.DistinguishedName ?? string.Empty,
                        search.DistinguishedName is "" or null ? [] : new() { ["description"] = ["readable value"] });
                });
                Connections.Add(connection); return new BoundLdapSession(connection, options, authentication, referrals);
            }, reusable: LdapConnectionProvider.CanReuse(options, referrals), preferFresh: fresh, minimumGeneration: minimum).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        public void Dispose() => Pool.Dispose();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Platform_authentication_uses_new_bound_resource_for_each_operation(bool ambient)
    {
        using var fixture = new Fixture();
        using var entry = fixture.Entry(authentication: AuthType.Negotiate, ambient: ambient);
        using (var first = entry.AcquireConnection())
        {
            Assert.True(LdapConnectionProvider.IsManagedSession(first.Connection));
            Assert.Equal(0, fixture.Connections[0].Disposals);
        }
        Assert.Equal(1, fixture.Connections[0].Disposals);
        using (var second = entry.AcquireConnection())
            Assert.NotSame(fixture.Connections[0], second.Connection);
        Assert.Equal(2, fixture.Connections.Count);
        Assert.All(fixture.Connections, connection => Assert.Equal(1, connection.Disposals));
        Assert.Equal(0, fixture.Pool.Snapshot.Reused);
    }

    [Fact]
    public void Bound_resource_outlives_lease_and_retires_exactly_once_without_replay()
    {
        using var fixture = new Fixture();
        using var entry = fixture.Entry();
        using (var first = entry.AcquireConnection()) { }
        Assert.Equal(0, fixture.Connections[0].Disposals);
        using (var second = entry.AcquireConnection())
        {
            Assert.Same(fixture.Connections[0], second.Connection);
            fixture.Failure = new InvalidOperationException("Interrupted send");
            Assert.Throws<InvalidOperationException>(() => second.Connection.SendRequestTracked(new SearchRequest()));
            Assert.Single(fixture.Requests);
        }
        Assert.Equal(1, fixture.Connections[0].Disposals);
        using (var replacement = entry.AcquireConnection())
            Assert.NotSame(fixture.Connections[0], replacement.Connection);
        Assert.Equal(2, fixture.Connections.Count);
        Assert.Single(fixture.Requests);
    }

    [Fact]
    public void Platform_operations_ignore_retained_primary_and_schema_handles()
    {
        using var fixture = new Fixture();
        using var entry = fixture.Entry(authentication: AuthType.Negotiate);
        var retained = Connection.Create(_ => throw new Exception("Retained identity used"));
        typeof(Entry).GetField("_connection", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(entry, retained);
        typeof(Entry).GetField("_schemaConnection", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(entry, retained);
        using var operation = entry.AcquireConnection();
        Assert.NotSame(retained, operation.Connection);
        Assert.Same(operation.Connection, entry.SchemaConnectionForOperation(operation.Connection));
        Assert.Throws<NotSupportedException>(() => entry.GetConnection());
    }

    [Fact]
    public void Controlled_offline_transport_permission_is_bound_to_exact_handles()
    {
        using var fixture = new Fixture();
        using var entry = fixture.Entry(authentication: AuthType.Negotiate);
        var controlled = Connection.Create(_ => throw new Exception("No request expected"));
        entry.SetControlledRetainedConnections(controlled);
        using (var operation = entry.AcquireConnection()) Assert.Same(controlled, operation.Connection);
        entry.Close();
        Assert.Equal(1, controlled.Disposals);
        var unrelated = Connection.Create(_ => throw new Exception("Unmarked transport used"));
        typeof(Entry).GetField("_connection", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(entry, unrelated);
        using var next = entry.AcquireConnection();
        Assert.NotSame(unrelated, next.Connection);
    }

    [Fact]
    public void Bound_resource_owns_snapshot_and_disposes_idempotently()
    {
        var options = new LdapConnectionOptions { Host = "offline.invalid", BindDn = "example", BindPassword = "synthetic" };
        var authentication = new LdapAuthenticationSource(options);
        var connection = Connection.Create(_ => throw new Exception("No requests expected"));
        var resource = new BoundLdapSession(connection, options, authentication, ReferralChasingOption.None);
        Assert.NotSame(options, resource.Profile);
        Assert.Same(authentication, resource.Authentication);
        Assert.Equal(ReferralChasingOption.None, resource.Referrals);
        resource.Dispose(); resource.Dispose();
        Assert.Equal(1, connection.Disposals);
        Assert.Throws<ObjectDisposedException>(() => resource.Connection);
    }

    private static SearchResponse Response(string dn, Dictionary<string, object[]> values, ResultCode code = ResultCode.Success)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var response = (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
            new object?[] { null, Array.Empty<DirectoryControl>(), code, null, Array.Empty<Uri>() }, null)!;
        var entry = (SearchResultEntry)Activator.CreateInstance(typeof(SearchResultEntry), flags, null, new object[] { dn }, null)!;
        foreach (var (name, data) in values)
            typeof(SearchResultAttributeCollection).GetMethod("Add", flags)!.Invoke(entry.Attributes, [name, new DirectoryAttribute(name, data)]);
        typeof(SearchResultEntryCollection).GetMethod("Add", flags)!.Invoke(response.Entries, [entry]);
        return response;
    }

    [Theory]
    [InlineData(AdForLinux.DirectoryServices.SearchScope.OneLevel, false)]
    [InlineData(AdForLinux.DirectoryServices.SearchScope.OneLevel, true)]
    [InlineData(AdForLinux.DirectoryServices.SearchScope.Subtree, false)]
    [InlineData(AdForLinux.DirectoryServices.SearchScope.Subtree, true)]
    public void FindOne_nonbase_is_one_bounded_request_and_preserves_partial_results(
        AdForLinux.DirectoryServices.SearchScope scope, bool partial)
    {
        using var fixture = new Fixture();
        using var root = fixture.Entry(defaultReferrals: true);
        using var searcher = new Searcher(root) { SearchScope = scope, SizeLimit = 20,
            CacheResults = false, ServerTimeLimit = TimeSpan.FromSeconds(5) };
        fixture.OnRequest = request =>
        {
            var search = Assert.IsType<SearchRequest>(request);
            bool operation = search.DistinguishedName == "CN=first" && !search.Attributes.Contains("1.1");
            fixture.Failure = operation && partial
                ? new DirectoryOperationException(Response("CN=first", new() { ["description"] = ["partial value"] }, ResultCode.SizeLimitExceeded))
                : null;
        };
        var result = searcher.FindOne();
        Assert.NotNull(result);
        Assert.Equal(partial ? "partial value" : "readable value", result.Properties["description"][0]);
        var requests = fixture.Requests.OfType<SearchRequest>().ToArray();
        Assert.Single(requests, r => r.DistinguishedName == "CN=first" && r.Attributes.Contains("1.1"));
        var sent = Assert.Single(requests, r => r.DistinguishedName == "CN=first" && !r.Attributes.Contains("1.1"));
        Assert.Equal((System.DirectoryServices.Protocols.SearchScope)(int)scope, sent.Scope);
        Assert.Equal(1, sent.SizeLimit); Assert.InRange(sent.TimeLimit, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        Assert.Empty(sent.Controls);
        // Delegate-backed ordinary routing only: this validates public request
        // construction/materialization, not WinLDAP continuation or scoped eligibility.
    }

    [Fact]
    public void Retained_entries_release_operation_leases_and_share_one_handle_across_different_dns()
    {
        using var fixture = new Fixture();
        using var first = fixture.Entry(); using var second = fixture.Entry("second");
        first.RefreshCache(["description"]);
        // First initialization of a new entry with Referral=None explicitly changes
        // its referral binding; subsequent calls can reuse the first successful bind.
        second.RefreshCache(["description"]);
        first.RefreshCache(["description"]);
        second.RefreshCache(["description"]);
        Assert.Equal("readable value", first.Properties["description"].Value);
        Assert.Equal(1, fixture.Pool.Snapshot.Total);
        Assert.True(fixture.Pool.Snapshot.Reused >= 2);
        Assert.Contains(fixture.Requests.OfType<SearchRequest>(), request => request.DistinguishedName == "CN=first");
        Assert.Contains(fixture.Requests.OfType<SearchRequest>(), request => request.DistinguishedName == "CN=second");
    }

    [Fact]
    public void Basic_entries_with_unchanged_default_referrals_use_platform_reuse_policy()
    {
        using var fixture = new Fixture();
        using var first = fixture.Entry(defaultReferrals: true);
        using var second = fixture.Entry("second", defaultReferrals: true);
        Assert.Equal(ReferralChasingOption.External, first.Options.Referral);
        first.RefreshCache(["description"]);
        second.RefreshCache(["description"]);
        first.RefreshCache(["description"]);
        if (OperatingSystem.IsLinux())
        {
            Assert.Single(fixture.Connections);
            Assert.True(fixture.Pool.Snapshot.Reused >= 2);
        }
        else
        {
            Assert.Equal(0, fixture.Pool.Snapshot.Reused);
            Assert.Equal(0, fixture.Pool.Snapshot.Total);
        }
        Assert.Equal(ReferralChasingOption.External, first.Options.Referral);
        Assert.Equal(ReferralChasingOption.External, second.Options.Referral);
    }

    [Fact]
    public void Buffered_search_materializes_schema_with_capacity_one()
    {
        using var fixture = new Fixture(); using var root = fixture.Entry();
        using var search = new Searcher(root) { ReferralChasing = ReferralChasingOption.None };
        search.PropertiesToLoad.Add("description");
        using var results = search.FindAll();
        Assert.Single(results.Cast<SearchResult>());
        Assert.Equal("readable value", results[0].Properties["description"][0]);
        Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
    }

    [Fact]
    public void Explicit_close_requires_fresh_bind_and_does_not_dispose_an_active_operation()
    {
        using var fixture = new Fixture(2); using var entry = fixture.Entry();
        entry.RefreshCache(["description"]);
        using var old = entry.AcquireConnection(); var oldConnection = (Connection)old.Connection;
        entry.Close(); entry.Options.Referral = ReferralChasingOption.None;
        Assert.Equal(0, oldConnection.Disposals);
        entry.RefreshCache(["description"]);
        old.Dispose();
        entry.RefreshCache(["description"]);
        Assert.Equal(1, oldConnection.Disposals);
        Assert.Equal(2, fixture.Connections.Count);
    }

    [Fact]
    public void Transport_failure_discards_once_and_write_is_never_replayed()
    {
        using var fixture = new Fixture(); using var entry = fixture.Entry();
        entry.RefreshCache(["description"]);
        var before = fixture.Requests.Count;
        fixture.Failure = new LdapException(81);
        Assert.ThrowsAny<System.Runtime.InteropServices.COMException>(() => entry.ReplaceAttributeImmediate("description", "changed"));
        Assert.Equal(before + 1, fixture.Requests.Count);
        Assert.Equal(0, fixture.Pool.Snapshot.Total);
        fixture.Failure = null; entry.RefreshCache(["description"]);
        Assert.Equal(2, fixture.Connections.Count);
    }

    [Fact]
    public void Ordinary_ldap_rejection_does_not_discard_a_healthy_operation_lease()
    {
        using var fixture = new Fixture(); using var entry = fixture.Entry();
        entry.RefreshCache(["description"]);
        fixture.Failure = new DirectoryOperationException(Response("CN=first", [], ResultCode.InsufficientAccessRights));
        Assert.ThrowsAny<System.Runtime.InteropServices.COMException>(() => entry.ReplaceAttributeImmediate("description", "changed"));
        Assert.Equal(1, fixture.Pool.Snapshot.Total);
        Assert.Equal(0, fixture.Connections[0].Disposals);
    }
    [Fact]
    public void Binding_and_search_origin_copies_preserve_close_freshness_floor()
    {
        using var fixture = new Fixture(3); using var entry = fixture.Entry();
        entry.RefreshCache(["description"]);
        using var old = entry.AcquireConnection(); var oldConnection = (Connection)old.Connection;
        entry.Close(); entry.Options.Referral = ReferralChasingOption.None;
        entry.RefreshCache(["description"]);
        var origin = new SearchResultOrigin(entry, entry.CaptureBindingAuthority());
        old.Dispose();
        using var copy = origin.Copy();
        using var pair = new LeasePair(copy.AcquireConnections(2, referrals: ReferralChasingOption.None));
        Assert.DoesNotContain(pair.Leases, lease => ReferenceEquals(oldConnection, lease.Connection));
        Assert.Equal(1, oldConnection.Disposals);
    }

    private sealed class LeasePair(Entry.ConnectionLease[] leases) : IDisposable
    {
        internal Entry.ConnectionLease[] Leases => leases;
        public void Dispose() { foreach (var lease in leases) lease.Dispose(); }
    }

    [Fact]
    public void Streaming_capacity_one_fails_before_native_request_and_releases_setup()
    {
        using var fixture = new Fixture(); using var root = fixture.Entry();
        using var search = new Searcher(root) { ReferralChasing = ReferralChasingOption.None, Asynchronous = true };
        search.ConfigureConnectionOverride = _ => { };
        Assert.Throws<InvalidOperationException>(() => search.FindAll());
        Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
        Assert.All(fixture.Requests, request => Assert.IsType<SearchRequest>(request));
        Assert.Equal(1, fixture.Pool.Snapshot.Total);
    }

    [Fact]
    public void Unpaged_search_permission_rejection_preserves_healthy_session()
    {
        using var fixture = new Fixture(); using var root = fixture.Entry();
        using var search = new Searcher(root) { ReferralChasing = ReferralChasingOption.None };
        using (var initial = search.FindAll()) Assert.Single(initial.Cast<SearchResult>());
        fixture.Failure = new DirectoryOperationException(Response("CN=first", [], ResultCode.InsufficientAccessRights));
        Assert.ThrowsAny<System.Runtime.InteropServices.COMException>(() => search.FindAll());
        Assert.Equal(1, fixture.Pool.Snapshot.Total); Assert.Equal(0, fixture.Connections[0].Disposals);
    }

    [Fact]
    public void Ranged_read_rejects_rebind_during_request_before_publishing_values()
    {
        using var fixture = new Fixture(); using var entry = fixture.Entry();
        fixture.OnRequest = _ => entry.Username = "different reader";
        Assert.Throws<InvalidOperationException>(() => RangedAttributeReader.Read(entry, "description"));
        Assert.Single(fixture.Requests);
        Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
    }

}
