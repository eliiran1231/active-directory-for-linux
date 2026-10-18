using System.Diagnostics;
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
}
