using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

// Same class keeps these real-provider tests in the existing exact native CI filter.
// Plaintext loopback, synthetic credentials, no trust or eligibility overrides.
public sealed partial class WindowsBasicReferralTests
{
    private static LdapConnectionOptions PoolOptions(WindowsReferralEndpoint endpoint,
        string identity = WindowsReferralEndpoint.FirstIdentity,
        string password = WindowsReferralEndpoint.Password, int seconds = 5) => new()
    {
        Host = "127.0.0.1", Port = endpoint.Port, UseSsl = false,
        AuthenticationType = AuthType.Basic, BindDn = identity, BindPassword = password,
        Timeout = TimeSpan.FromSeconds(seconds),
    };

    // Runs after all active leases are disposed, while the endpoint is still alive.
    // PreferFresh retires every idle value for this exact key. Invalidate the one
    // cleanup bind too, so assertion failures cannot leave fixture handles pooled.
    private sealed class PoolKeyCleanup(LdapConnectionOptions options) : IDisposable
    {
        public void Dispose()
        {
            using var cleanup = LdapConnectionProvider.Acquire(options, preferFresh: true);
            cleanup.Invalidate();
        }
    }

    [WindowsReferralFact]
    public async Task Production_pool_exact_credentials_and_timeout_are_isolated()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        using var first = LdapConnectionProvider.Acquire(options);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, first.Execute(Read));
        var connection = first.Connection;
        first.Dispose();
        using var second = LdapConnectionProvider.Acquire(PoolOptions(endpoint, WindowsReferralEndpoint.SecondIdentity));
        second.Invalidate();
        Assert.NotSame(connection, second.Connection);
        Assert.Equal(WindowsReferralEndpoint.SecondIdentity, second.Execute(Read));
        using var timeout = LdapConnectionProvider.Acquire(PoolOptions(endpoint, seconds: 7));
        timeout.Invalidate();
        Assert.NotSame(connection, timeout.Connection);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, timeout.Execute(Read));
        Assert.Throws<LdapException>(() =>
        {
            using var unexpected = LdapConnectionProvider.Acquire(PoolOptions(endpoint, password: "wrong synthetic password"));
            unexpected.Invalidate();
        });
        Assert.Equal(4, endpoint.Binds);
        using var reused = LdapConnectionProvider.Acquire(options);
        reused.Invalidate(); // Always clean up this fixture's pooled handle, even on assertion failure.
        Assert.Same(connection, reused.Connection);
        Assert.Equal(4, endpoint.Binds);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, reused.Execute(Read));
    }

    [WindowsReferralFact]
    public async Task Production_pool_batch_leases_are_exclusive_and_freshness_rejects_late_return()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        var leases = LdapConnectionProvider.AcquireBatch(options, 2);
        try
        {
            Assert.NotSame(leases[0].Connection, leases[1].Connection);
            foreach (var lease in leases)
                Assert.Equal(WindowsReferralEndpoint.FirstIdentity, lease.Execute(Read));
            var old = leases[0].Connection;
            var generation = LdapConnectionProvider.NewGeneration();
            using var fresh = LdapConnectionProvider.Acquire(options, preferFresh: true, minimumGeneration: generation);
            fresh.Invalidate();
            Assert.NotSame(old, fresh.Connection);
            leases[0].Dispose(); // Return an older active lease after the freshness boundary.
            using var next = LdapConnectionProvider.Acquire(options, minimumGeneration: generation);
            next.Invalidate();
            Assert.NotSame(old, next.Connection);
            Assert.Equal(WindowsReferralEndpoint.FirstIdentity, next.Execute(Read));
            Assert.Equal(4, endpoint.Binds);
        }
        finally
        {
            foreach (var lease in leases) { lease.Invalidate(); lease.Dispose(); }
        }
    }

    [WindowsReferralFact]
    public async Task Production_pool_transport_failure_evicts_without_managed_replay()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        using var failed = LdapConnectionProvider.Acquire(options);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, failed.Execute(Read));
        var old = failed.Connection;
        endpoint.DisconnectOnSearch = true;
        var attempts = 0;
        var error = Assert.Throws<DirectoryOperationException>(() => failed.Execute(c => { attempts++; return Read(c); }));
        Assert.NotNull(error.Response);
        Assert.Equal(ResultCode.Unavailable, error.Response.ResultCode);
        Assert.Equal(1, attempts);
        failed.Dispose();
        var bindsBeforeRecovery = endpoint.Binds;
        endpoint.DisconnectOnSearch = false;
        using var replacement = LdapConnectionProvider.Acquire(options);
        replacement.Invalidate();
        Assert.NotSame(old, replacement.Connection);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, replacement.Execute(Read));
        Assert.Equal(bindsBeforeRecovery + 1, endpoint.Binds);
        output.WriteLine($"Failed operation invoked once by provider; native binds before recovery={bindsBeforeRecovery}; recovery added one bind.");
    }

    [WindowsReferralFact]
    public async Task Production_pool_plaintext_lease_survives_existing_anonymous_scope()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        using var original = LdapConnectionProvider.Acquire(options);
        var connection = original.Connection;
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, original.Execute(Read));
        original.Dispose();
        AsAnonymous(() =>
        {
            using var anonymous = LdapConnectionProvider.Acquire(options);
            Assert.Same(connection, anonymous.Connection);
            Assert.Equal(WindowsReferralEndpoint.FirstIdentity, anonymous.Execute(Read));
        });
        using var restored = LdapConnectionProvider.Acquire(options);
        restored.Invalidate();
        Assert.Same(connection, restored.Connection);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, restored.Execute(Read));
        Assert.Equal(1, endpoint.Binds);
        Assert.Equal(3, endpoint.Searches);
        Assert.Equal(0, endpoint.AnonymousBinds);
        Assert.Equal(0, endpoint.SaslBinds);
    }

    [WindowsReferralFact]
    public async Task Production_pool_full_key_capacity_honors_cancellation_without_sharing_a_lease()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        var leases = LdapConnectionProvider.AcquireBatch(options, 8);
        try
        {
            Assert.Equal(8, leases.Select(lease => lease.Connection).Distinct().Count());
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            Assert.Throws<OperationCanceledException>(() =>
            {
                using var unexpected = LdapConnectionProvider.Acquire(options, cancellation.Token);
                unexpected.Invalidate();
            });
            Assert.Equal(8, endpoint.Binds);
            var returned = leases[0].Connection;
            leases[0].Dispose();
            using var admitted = LdapConnectionProvider.Acquire(options);
            admitted.Invalidate();
            Assert.Same(returned, admitted.Connection);
            Assert.Equal(WindowsReferralEndpoint.FirstIdentity, admitted.Execute(Read));
            Assert.Equal(8, endpoint.Binds);
        }
        finally
        {
            foreach (var lease in leases) { lease.Invalidate(); lease.Dispose(); }
        }
    }

    [WindowsReferralFact]
    public async Task Production_pool_referral_policy_transition_keeps_Windows_guard()
    {
        await using var endpoint = new WindowsReferralEndpoint(tls: false);
        var options = PoolOptions(endpoint);
        using var cleanup = new PoolKeyCleanup(options);
        using var pooled = LdapConnectionProvider.Acquire(options);
        var original = pooled.Connection;
        pooled.Dispose();
        using var external = LdapConnectionProvider.Acquire(options, referrals: ReferralChasingOption.External);
        Assert.False(LdapConnectionProvider.CanReuse(options, ReferralChasingOption.External));
        Assert.NotSame(original, external.Connection);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, external.Execute(Read));
        var externalConnection = external.Connection;
        external.Dispose();
        using var nextExternal = LdapConnectionProvider.Acquire(options, referrals: ReferralChasingOption.External);
        Assert.NotSame(externalConnection, nextExternal.Connection);
        using var restored = LdapConnectionProvider.Acquire(options);
        restored.Invalidate();
        Assert.Same(original, restored.Connection);
        Assert.Equal(WindowsReferralEndpoint.FirstIdentity, restored.Execute(Read));
        Assert.Equal(3, endpoint.Binds);
    }
}
