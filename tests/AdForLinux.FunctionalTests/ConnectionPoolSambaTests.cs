using System.Diagnostics;
using System.DirectoryServices.Protocols;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;
using SearchScope = AdForLinux.DirectoryServices.SearchScope;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Xunit.Abstractions;

namespace AdForLinux.FunctionalTests;

[CollectionDefinition("Connection pool measurements", DisableParallelization = true)]
public sealed class ConnectionPoolMeasurementCollection;

// Live tests: deliberately excluded from the offline runner. Run only in disposable Samba CI.
[Collection("Connection pool measurements")]
public class ConnectionPoolSambaTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Default_referrals_reach_Samba_and_reuse_the_same_basic_session()
    {
        var scheme = TestSettings.UseTls ? "ldaps" : "ldap";
        await using var source = new LoopbackReferralServer($"{scheme}://{TestSettings.Host}:{TestSettings.Port}/");
        var options = new LdapConnectionOptions
        {
            Host = "127.0.0.1", Port = source.Port, UseSsl = false,
            BindDn = "synthetic referral reader", BindPassword = "synthetic test password",
            Timeout = TimeSpan.FromSeconds(10),
        };
        using var entry = new Entry($"LDAP://127.0.0.1:{source.Port}", options);
        Assert.Equal(ReferralChasingOption.External, entry.Options.Referral);
        LdapConnection? first = null;
        for (var i = 0; i < 3; i++)
        {
            using var lease = entry.AcquireConnection();
            try
            {
                if (first is not null) Assert.Same(first, lease.Connection);
                first = lease.Connection;
                // The source returns only a referral. This attribute must be read
                // from the real disposable Samba target by native referral chasing.
                Assert.Equal(TestSettings.BaseDn,
                    RootDse.Read(lease.Connection, "defaultNamingContext")["defaultNamingContext"]);
            }
            catch
            {
                lease.Invalidate();
                throw;
            }
            finally
            {
                if (i == 2) lease.Invalidate(); // Close fixture sockets before teardown.
            }
        }
        Assert.Equal(1, source.Binds);
        Assert.Equal(3, source.Searches);
        Assert.Equal(ReferralChasingOption.External, entry.Options.Referral);
        output.WriteLine("Three native referrals reached disposable Samba using one primary Basic bind; native child socket/bind counts are not measured.");
    }

    [Fact]
    public void RootDse_sequence_reuses_bound_connection_and_records_before_after_counts()
    {
        using var context = TestSettings.CreatePrincipalContext();
        var options = context.BuildOptions().Clone(TimeSpan.FromSeconds(29));
        const int operations = 20;
        var before = Stopwatch.StartNew();
        for (var i = 0; i < operations; i++)
        {
            using var connection = LdapConnectionFactory.CreateBound(options);
            Assert.NotEmpty(RootDse.Read(connection, "defaultNamingContext"));
        }
        before.Stop();
        var countsBefore = LdapConnectionProvider.Snapshot;
        var after = Stopwatch.StartNew();
        for (var i = 0; i < operations; i++)
            Assert.NotEmpty(LdapConnectionProvider.Execute(options, connection => RootDse.Read(connection, "defaultNamingContext")));
        after.Stop();
        var countsAfter = LdapConnectionProvider.Snapshot;
        var creations = countsAfter.Created - countsBefore.Created;
        var reuse = countsAfter.Reused - countsBefore.Reused;
        Assert.InRange(creations, 0, 1);
        Assert.Equal(operations, creations + reuse);
        // Each successful factory initialization has exactly one explicit bind; checkout has none.
        output.WriteLine($"RootDSE {operations} operations: direct creation/bind={operations}/{operations}, elapsed={before.Elapsed.TotalMilliseconds:F2}ms; pooled creation/bind={creations}/{creations}, reuse={reuse}, elapsed={after.Elapsed.TotalMilliseconds:F2}ms.");
        output.WriteLine("Single-process disposable Samba measurement; not live AD parity, tail latency, failover or throughput evidence.");
    }

    [Fact]
    public void Warm_discovery_does_not_make_credential_validation_accept_invalid_password()
    {
        using var context = TestSettings.CreatePrincipalContext();
        Assert.NotEmpty(context.ConnectedServer);
        Assert.False(context.ValidateCredentials(TestSettings.BindDn, "deliberately incorrect test password", TestSettings.PrincipalContextOptions));
        Assert.True(context.ValidateCredentials(TestSettings.BindDn, TestSettings.BindPassword, TestSettings.PrincipalContextOptions));
    }
    [Fact]
    public void Retained_entry_read_sequence_records_creation_and_bind_reduction()
    {
        using var context = TestSettings.CreatePrincipalContext();
        var options = context.BuildOptions().Clone(TimeSpan.FromSeconds(27));
        const int operations = 20;
        var direct = Stopwatch.StartNew();
        for (var i = 0; i < operations; i++)
        {
            using var connection = LdapConnectionFactory.CreateBound(options);
            var response = (SearchResponse)connection.SendRequest(new SearchRequest(TestSettings.BaseDn,
                "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, "distinguishedName"));
            Assert.Single(response.Entries.Cast<SearchResultEntry>());
        }
        direct.Stop();
        var before = LdapConnectionProvider.Snapshot;
        var pooled = Stopwatch.StartNew();
        for (var i = 0; i < operations; i++)
        {
            using var entry = new Entry(TestSettings.PathFor(TestSettings.BaseDn), options.Clone());
            Assert.Equal(ReferralChasingOption.External, entry.Options.Referral);
            entry.RefreshCache(["distinguishedName"]);
            Assert.NotNull(entry.Properties["distinguishedName"].Value);
        }
        pooled.Stop();
        var after = LdapConnectionProvider.Snapshot;
        var creations = after.Created - before.Created;
        Assert.InRange(creations, 0, 1);
        Assert.True(after.Reused - before.Reused >= operations - 1);
        output.WriteLine($"Entry reads {operations} operations: direct creation/bind={operations}/{operations}, elapsed={direct.Elapsed.TotalMilliseconds:F2}ms; pooled creation/bind={creations}/{creations}, reuse={after.Reused - before.Reused}, elapsed={pooled.Elapsed.TotalMilliseconds:F2}ms.");
        output.WriteLine("Direct raw LDAP versus public entry materialization (including schema work); explicit successful factory binds, not wire-bind instrumentation or general AD performance parity.");
    }

    [Fact]
    public void Buffered_and_streaming_pages_match_and_early_disposal_releases_capacity()
    {
        using var context = TestSettings.CreatePrincipalContext();
        var options = context.BuildOptions().Clone(TimeSpan.FromSeconds(26));
        using var root = new Entry(TestSettings.PathFor(TestSettings.BaseDn), options);
        Assert.Equal(ReferralChasingOption.External, root.Options.Referral);
        using var search = new Searcher(root)
        {
            SearchScope = SearchScope.OneLevel, PageSize = 2,
        };
        Assert.Equal(ReferralChasingOption.External, search.ReferralChasing);
        search.PropertiesToLoad.Add("distinguishedName");
        using var buffered = search.FindAll();
        var expected = buffered.Cast<AdForLinux.DirectoryServices.SearchResult>().Select(result => result.Path).Order().ToArray();
        Assert.NotEmpty(expected);
        search.Asynchronous = true;
        using (var streaming = search.FindAll())
            Assert.Equal(expected, streaming.Cast<AdForLinux.DirectoryServices.SearchResult>().Select(result => result.Path).Order().ToArray());
        using (var abandoned = search.FindAll())
        {
            using var iterator = abandoned.Cast<AdForLinux.DirectoryServices.SearchResult>().GetEnumerator();
            Assert.True(iterator.MoveNext());
        }
        // Admission of the entire same-key cap proves the producer returned or
        // discarded both leases after early collection disposal, without a sleep.
        var all = LdapConnectionProvider.AcquireBatch(options, 8, referrals: ReferralChasingOption.External);
        foreach (var session in all) session.Dispose();
    }

    [Fact]
    public void Concurrent_entry_reads_respect_managed_per_key_capacity()
    {
        using var context = TestSettings.CreatePrincipalContext();
        var options = context.BuildOptions().Clone(TimeSpan.FromSeconds(25));
        var before = LdapConnectionProvider.Snapshot;
        Parallel.For(0, 24, new ParallelOptions { MaxDegreeOfParallelism = 12 }, _ =>
        {
            using var entry = new Entry(TestSettings.PathFor(TestSettings.BaseDn), options.Clone());
            Assert.Equal(ReferralChasingOption.External, entry.Options.Referral);
            entry.RefreshCache(["distinguishedName"]);
            Assert.NotNull(entry.Properties["distinguishedName"].Value);
        });
        var after = LdapConnectionProvider.Snapshot;
        Assert.InRange(after.Created - before.Created, 1, 8);
        output.WriteLine($"Concurrent entry reads: 24 operations, up to 12 workers, creation/bind={after.Created - before.Created}/{after.Created - before.Created}, reuse={after.Reused - before.Reused}.");
    }

}
