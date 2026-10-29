using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class ConnectionPoolTests
{
    [Theory]
    [InlineData(AuthType.Negotiate, null, (int)LdapAuthenticationProvenance.AmbientPlatform)]
    [InlineData(AuthType.Negotiate, "EXAMPLE\\reader", (int)LdapAuthenticationProvenance.ExplicitPlatform)]
    [InlineData(AuthType.Anonymous, null, (int)LdapAuthenticationProvenance.Anonymous)]
    public void Unknown_authority_never_grants_reuse(AuthType mechanism, string? identity,
        int provenance)
    {
        var source = new LdapAuthenticationSource(new LdapConnectionOptions
        { Host = "service-target.invalid", AuthenticationType = mechanism, BindDn = identity, BindPassword = "synthetic" });
        Assert.Equal((LdapAuthenticationProvenance)provenance, source.Provenance);
        foreach (var referrals in Enum.GetValues<ReferralChasingOption>())
        {
            Assert.Equal(LdapAuthenticationCapabilities.None, source.Capabilities(referrals));
            Assert.Equal(LdapSessionFreshness.FreshBind, source.Freshness(referrals));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Both_namespaces_and_derived_entries_preserve_platform_policy(bool explicitIdentity)
    {
        var user = explicitIdentity ? "EXAMPLE\\reader" : null;
        var password = explicitIdentity ? "synthetic" : null;
        using var entry = new DirectoryEntry("LDAP://directory.invalid/DC=example", user, password,
            AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing);
        using var context = new AdForLinux.DirectoryServices.AccountManagement.PrincipalContext(
            AdForLinux.DirectoryServices.AccountManagement.ContextType.Domain, "directory.invalid", "DC=example",
            AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Negotiate |
            AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Signing |
            AdForLinux.DirectoryServices.AccountManagement.ContextOptions.Sealing, user, password);
        using var derived = context.CreateDirectoryEntry("CN=reader,DC=example");
        var recipes = new[] { entry.BuildOptions(), context.BuildOptions(), derived.BuildOptions() };
        var expected = LdapConnectionProvider.ConnectionKey.Create(recipes[0], ReferralChasingOption.None);
        foreach (var recipe in recipes)
        {
            Assert.Equal(expected, LdapConnectionProvider.ConnectionKey.Create(recipe, ReferralChasingOption.None));
            Assert.Equal(LdapSessionFreshness.FreshBind,
                new LdapAuthenticationSource(recipe).Freshness(ReferralChasingOption.None));
            Assert.True(recipe.Signing); Assert.True(recipe.Sealing);
        }
    }

    [Fact]
    public void Native_binder_capability_does_not_enable_facade_transport_or_relax_profile()
    {
        var options = new LdapConnectionOptions { Host = "directory.invalid", Port = 389, UseSsl = false,
            AuthenticationType = AuthType.Negotiate, Signing = true, Sealing = true };
        Assert.False(NativeLdapBindingBackend.SupportsFacadeRequests);
        Assert.Equal(OperatingSystem.IsLinux(), NativeLdapBindingBackend.CanRepresentBinding(options, ReferralChasingOption.None));
        Assert.False(NativeLdapBindingBackend.CanRepresentBinding(options, ReferralChasingOption.All));
        Assert.False(NativeLdapBindingBackend.CanRepresentBinding(new LdapConnectionOptions
        { Host = "directory.invalid", UseSsl = true, AuthenticationType = AuthType.Negotiate, Signing = true }, ReferralChasingOption.None));
        Assert.False(NativeLdapBindingBackend.CanRepresentBinding(new LdapConnectionOptions
        { Host = "directory.invalid", UseSsl = false, AuthenticationType = AuthType.Negotiate, Signing = true, BindDn = "reader" }, ReferralChasingOption.None));
        Assert.False(NativeLdapBindingBackend.CanRepresentBinding(new LdapConnectionOptions
        { Host = "directory..invalid", UseSsl = false, AuthenticationType = AuthType.Negotiate, Signing = true }, ReferralChasingOption.None));
        // Unsupported operating systems reject the profile before the offline
        // guard; neither branch loads a native library or reads a cache.
        if (!OperatingSystem.IsLinux())
        {
            Assert.Throws<PlatformNotSupportedException>(() => NativeLdapBindingBackend.ResolveForBinding(options, ReferralChasingOption.None));
            return;
        }
        var error = Assert.Throws<InvalidOperationException>(() => NativeLdapBindingBackend.ResolveForBinding(options, ReferralChasingOption.None));
        Assert.Equal(OfflineTestGuard.Message, error.Message);
    }

    private sealed class Resource : IDisposable
    {
        internal int Disposals;
        internal int Users;
        internal Action? OnDispose;
        public void Dispose() { Interlocked.Increment(ref Disposals); OnDispose?.Invoke(); }
    }
    private sealed class Clock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        internal void Advance(int seconds) => Interlocked.Add(ref ticks, TimeSpan.FromSeconds(seconds).Ticks);
    }
    private static BoundedConnectionPool<string, Resource> Pool(int perKey = 1, int total = 2, Clock? clock = null,
        TimeSpan? timeout = null) => new(perKey, total, clock: clock, acquisitionTimeout: timeout, startTimer: false);
    private static Task<T> Start<T>(Func<T> operation) => Task.Factory.StartNew(operation,
        CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    private static void Until(Func<bool> condition) => Assert.True(SpinWait.SpinUntil(condition, TimeSpan.FromSeconds(10)));

    [Fact]
    public void Reuses_exclusively_and_double_return_is_harmless()
    {
        using var pool = Pool();
        var first = pool.Acquire("directory", () => new Resource());
        var resource = first.Value;
        first.Dispose(); first.Dispose();
        Assert.Throws<ObjectDisposedException>(() => first.Value);
        using var second = pool.Acquire("directory", () => throw new Exception("Unexpected creation"));
        Assert.Same(resource, second.Value);
        Assert.Equal(1, pool.Snapshot.Total);
        Assert.Equal(1, pool.Snapshot.Reused);
    }

    [Fact]
    public void Idle_age_starts_at_return_and_active_connections_do_not_expire()
    {
        var clock = new Clock();
        using var pool = Pool(clock: clock);
        var first = pool.Acquire("directory", () => new Resource());
        var resource = first.Value;
        clock.Advance(600); pool.Sweep();
        Assert.Equal(0, resource.Disposals);
        first.Dispose(); clock.Advance(59); pool.Sweep();
        var second = pool.Acquire("directory", () => throw new Exception("Unexpected creation"));
        Assert.Same(resource, second.Value);
        second.Dispose(); clock.Advance(59); pool.Sweep();
        Assert.Equal(0, resource.Disposals);
        clock.Advance(1); pool.Sweep();
        Assert.Equal(1, resource.Disposals);
        Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public void Acquire_rejects_expired_idle_without_waiting_for_sweep()
    {
        var clock = new Clock();
        using var pool = Pool(clock: clock);
        var first = pool.Acquire("directory", () => new Resource());
        var old = first.Value; first.Dispose(); clock.Advance(60);
        using var second = pool.Acquire("directory", () => new Resource());
        Assert.NotSame(old, second.Value); Assert.Equal(1, old.Disposals);
    }

    [Fact]
    public async Task Capacity_waiter_receives_returned_connection_without_extra_creation()
    {
        using var pool = Pool();
        var first = pool.Acquire("directory", () => new Resource());
        var old = first.Value;
        var waiting = Start(() => pool.Acquire("directory", () => throw new Exception("Cap exceeded")));
        Until(() => pool.Snapshot.Waiting == 1);
        Assert.Equal(1, pool.Snapshot.Total);
        first.Dispose();
        using var second = await waiting.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Same(old, second.Value);
    }

    [Fact]
    public async Task Cancelled_waiter_has_no_key_or_reservation_and_does_not_consume_a_return()
    {
        using var pool = Pool(total: 1);
        using var first = pool.Acquire("first", () => new Resource());
        using var cancellation = new CancellationTokenSource();
        var waiting = Start(() => pool.Acquire("second", () => new Resource(), cancellation.Token));
        Until(() => pool.Snapshot.Waiting == 1);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await waiting);
        Assert.Equal(1, pool.Snapshot.Total); Assert.Equal(1, pool.Snapshot.Keys); Assert.Equal(0, pool.Snapshot.Waiting);
    }

    [Fact]
    public void Timeout_is_bounded_and_does_not_allocate()
    {
        using var pool = Pool(timeout: TimeSpan.FromMilliseconds(30));
        using var first = pool.Acquire("directory", () => new Resource());
        Assert.Throws<TimeoutException>(() => pool.Acquire("directory", () => throw new Exception("Cap exceeded")));
        Assert.Equal(1, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Waiting);
    }

    [Fact]
    public void Global_capacity_reclaims_incompatible_idle_keys()
    {
        using var pool = Pool(total: 1);
        var first = pool.Acquire("first", () => new Resource());
        var old = first.Value; first.Dispose();
        using var second = pool.Acquire("second", () => new Resource());
        Assert.Equal(1, old.Disposals); Assert.Equal(1, pool.Snapshot.Total); Assert.Equal(1, pool.Snapshot.Keys);
    }

    [Fact]
    public void Failed_initialization_and_invalidated_returns_release_capacity()
    {
        using var pool = Pool();
        Assert.Throws<InvalidOperationException>(() => pool.Acquire("directory", () => throw new InvalidOperationException()));
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Keys);
        var lease = pool.Acquire("directory", () => new Resource());
        var old = lease.Value; lease.Invalidate(); lease.Dispose();
        Assert.Equal(1, old.Disposals); Assert.Equal(0, pool.Snapshot.Total);
        using var next = pool.Acquire("directory", () => new Resource()); Assert.NotSame(old, next.Value);
    }

    [Fact]
    public async Task Creation_reservation_counts_toward_caps_and_shutdown_rejects_late_creation()
    {
        using var pool = Pool(total: 1);
        using var entered = new ManualResetEventSlim(); using var finish = new ManualResetEventSlim();
        var resource = new Resource();
        var creation = Start(() => pool.Acquire("directory", () => { entered.Set(); Assert.True(finish.Wait(10000)); return resource; }));
        Assert.True(entered.Wait(10000)); Assert.Equal(1, pool.Snapshot.Total);
        var waiting = Start(() => pool.Acquire("other", () => new Resource()));
        Until(() => pool.Snapshot.Waiting == 1);
        pool.Dispose(); finish.Set();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await creation);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await waiting);
        Assert.Equal(1, resource.Disposals); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public async Task Cancelled_creation_disposes_before_releasing_its_reservation()
    {
        using var pool = Pool(total: 1); using var token = new CancellationTokenSource();
        using var entered = new ManualResetEventSlim(); using var finish = new ManualResetEventSlim();
        var resource = new Resource();
        var task = Start(() => pool.Acquire("directory", () => { entered.Set(); Assert.True(finish.Wait(10000)); return resource; }, token.Token));
        Assert.True(entered.Wait(10000)); token.Cancel(); finish.Set();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
        Assert.Equal(1, resource.Disposals); Assert.Equal(0, pool.Snapshot.Total);
    }

    [Fact]
    public void Shutdown_drains_idle_and_defers_active_disposal_until_return()
    {
        var pool = Pool(perKey: 2);
        var first = pool.Acquire("directory", () => new Resource());
        var second = pool.Acquire("directory", () => new Resource());
        var idle = first.Value; var active = second.Value; first.Dispose();
        pool.Dispose(); pool.Dispose();
        Assert.Equal(1, idle.Disposals); Assert.Equal(0, active.Disposals);
        Assert.Throws<ObjectDisposedException>(() => pool.Acquire("directory", () => new Resource()));
        second.Dispose(); Assert.Equal(1, active.Disposals); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public void Disposal_failure_does_not_leak_capacity()
    {
        using var pool = Pool();
        var lease = pool.Acquire("directory", () => new Resource { OnDispose = () => throw new Exception("Synthetic disposal failure") });
        lease.Invalidate(); lease.Dispose();
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(1, pool.Snapshot.Failures);
    }

    [Fact]
    public async Task Adversarial_acquire_return_sweep_and_shutdown_never_share_or_double_dispose()
    {
        var clock = new Clock(); using var pool = Pool(perKey: 3, total: 5, clock: clock);
        var resources = new ConcurrentBag<Resource>();
        var workers = Enumerable.Range(0, 12).Select(worker => Start(() =>
        {
            for (var i = 0; i < 100; i++)
            {
                try
                {
                    using var lease = pool.Acquire("directory-" + worker % 3, () => { var value = new Resource(); resources.Add(value); return value; });
                    var value = lease.Value;
                    Assert.Equal(1, Interlocked.Increment(ref value.Users));
                    Assert.Equal(0, value.Disposals); Assert.InRange(pool.Snapshot.Total, 1, 5);
                    Thread.Yield();
                    Assert.Equal(0, Interlocked.Decrement(ref value.Users));
                    if (i % 7 == 0) lease.Invalidate();
                }
                catch (ObjectDisposedException) { break; }
                if (i % 11 == 0) { clock.Advance(60); pool.Sweep(); }
            }
            return true;
        })).ToArray();
        await Task.WhenAll(workers).WaitAsync(TimeSpan.FromSeconds(30));
        pool.Dispose();
        Assert.All(resources, value => Assert.Equal(1, value.Disposals));
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public void Key_isolates_every_setting_and_has_no_entry_identifier()
    {
        static LdapConnectionProvider.ConnectionKey Key(LdapConnectionOptions options) => LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None);
        var original = new LdapConnectionOptions { Host = "directory.example", BindDn = "reader", BindPassword = "first password" };
        Assert.Equal(Key(original), Key(original.Clone()));
        var alternatives = new[]
        {
            new LdapConnectionOptions { Host = "another.example", BindDn = "reader", BindPassword = "first password" },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "second password" },
            new LdapConnectionOptions { Host = original.Host, BindDn = "another reader", BindPassword = "first password" },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", Port = 389 },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", UseSsl = false },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", UseStartTls = true },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", SkipCertificateCheck = true },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", AuthenticationType = AuthType.Negotiate },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", Signing = true },
            new LdapConnectionOptions { Host = original.Host, BindDn = "reader", BindPassword = "first password", Sealing = true },
            original.Clone(timeout: TimeSpan.FromSeconds(20)),
        };
        Assert.All(alternatives, alternative => Assert.NotEqual(Key(original), Key(alternative)));
        Assert.NotEqual(Key(original), LdapConnectionProvider.ConnectionKey.Create(original, ReferralChasingOption.All));
        Assert.DoesNotContain("reader", Key(original).ToString());
        Assert.DoesNotContain("password", Key(original).ToString());
        Assert.DoesNotContain(original.Host, Key(original).ToString());
    }

    [Fact]
    public void Only_explicit_basic_credentials_are_reusable()
    {
        Assert.True(LdapConnectionProvider.CanReuse(new() { Host = "directory.example", BindDn = "reader", BindPassword = "password" }));
        foreach (var auth in Enum.GetValues<AuthType>().Where(auth => auth != AuthType.Basic))
            Assert.False(LdapConnectionProvider.CanReuse(new() { Host = "directory.example", AuthenticationType = auth, BindDn = "reader", BindPassword = "password" }));
        Assert.False(LdapConnectionProvider.CanReuse(new() { Host = "directory.example" }));
        Assert.False(LdapConnectionProvider.CanReuse(new() { Host = "directory.example", BindDn = "reader", BindPassword = "" }));
    }

    [Theory]
    [InlineData(ReferralChasingOption.None)]
    [InlineData(ReferralChasingOption.Subordinate)]
    [InlineData(ReferralChasingOption.External)]
    [InlineData(ReferralChasingOption.All)]
    public void Referral_policy_never_makes_ambient_or_other_authentication_reusable(ReferralChasingOption referrals)
    {
        var basic = new LdapConnectionOptions { Host = "directory.example", BindDn = "reader", BindPassword = "password" };
        Assert.Equal(referrals == ReferralChasingOption.None || OperatingSystem.IsLinux(),
            LdapConnectionProvider.CanReuse(basic, referrals));
        foreach (var auth in Enum.GetValues<AuthType>().Where(auth => auth != AuthType.Basic))
        {
            var other = new LdapConnectionOptions
            {
                Host = "directory.example", BindDn = "reader", BindPassword = "password", AuthenticationType = auth,
            };
            Assert.False(LdapConnectionProvider.CanReuse(other, referrals));
        }
        Assert.False(LdapConnectionProvider.CanReuse(new()
            { Host = "directory.example", BindDn = "reader" }, referrals));
        Assert.False(LdapConnectionProvider.CanReuse(new()
            { Host = "directory.example", BindPassword = "password" }, referrals));
    }

    [Fact]
    public void Referral_modes_and_explicit_identities_never_share_a_key()
    {
        var keys = new List<LdapConnectionProvider.ConnectionKey>();
        foreach (var referrals in Enum.GetValues<ReferralChasingOption>())
        foreach (var identity in new[] { "first reader", "second reader" })
        foreach (var password in new[] { "original password", "replacement password" })
            keys.Add(LdapConnectionProvider.ConnectionKey.Create(new()
            {
                Host = "directory.example", BindDn = identity, BindPassword = password,
            }, referrals));
        Assert.Equal(keys.Count, keys.Distinct().Count());
    }

    [Fact]
    public void Nonreusable_lease_is_destroyed_even_after_success()
    {
        using var pool = Pool();
        var lease = pool.Acquire("directory", () => new Resource(), reusable: false);
        var value = lease.Value; lease.Dispose(); Assert.Equal(1, value.Disposals); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public async Task Shutdown_races_with_return_sweep_and_blocked_acquisition()
    {
        for (var round = 0; round < 25; round++)
        {
            var clock = new Clock(); using var pool = Pool(clock: clock, total: 1);
            var lease = pool.Acquire("directory", () => new Resource()); var value = lease.Value;
            using var start = new ManualResetEventSlim();
            var waiter = Start(() =>
            {
                start.Wait();
                try { using var next = pool.Acquire("directory", () => new Resource()); }
                catch (ObjectDisposedException) { }
                return true;
            });
            var returning = Start(() => { start.Wait(); lease.Dispose(); lease.Dispose(); return true; });
            var sweep = Start(() => { start.Wait(); clock.Advance(60); pool.Sweep(); return true; });
            var shutdown = Start(() => { start.Wait(); pool.Dispose(); return true; });
            start.Set();
            await Task.WhenAll(waiter, returning, sweep, shutdown).WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(1, value.Disposals); Assert.Equal(0, pool.Snapshot.Total);
        }
    }

    [Fact]
    public async Task Destruction_keeps_capacity_reserved_until_physical_disposal_finishes()
    {
        using var pool = Pool(total: 1);
        using var entered = new ManualResetEventSlim(); using var finish = new ManualResetEventSlim();
        var lease = pool.Acquire("directory", () => new Resource { OnDispose = () => { entered.Set(); Assert.True(finish.Wait(10000)); } });
        lease.Invalidate(); var disposing = Start(() => { lease.Dispose(); return true; });
        Assert.True(entered.Wait(10000));
        var acquiring = Start(() => pool.Acquire("other", () => new Resource()));
        Until(() => pool.Snapshot.Waiting == 1); Assert.Equal(1, pool.Snapshot.Total);
        finish.Set(); await disposing;
        using var next = await acquiring.WaitAsync(TimeSpan.FromSeconds(10)); Assert.Equal(1, pool.Snapshot.Total);
    }

    [Fact]
    public void Ordinary_ldap_rejections_preserve_health_and_transport_failures_do_not()
    {
        static DirectoryOperationException Failure(ResultCode result) => new((SearchResponse)Activator.CreateInstance(
            typeof(SearchResponse), System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
            null, new object?[] { null, Array.Empty<DirectoryControl>(), result, null, Array.Empty<Uri>() }, null)!);
        foreach (var result in new[] { ResultCode.InsufficientAccessRights, ResultCode.NoSuchObject, ResultCode.ConstraintViolation })
        {
            Assert.False(LdapConnectionProvider.IsConnectionFailure(Failure(result)));
            Assert.False(LdapConnectionProvider.IsConnectionFailure(LdapExceptionTranslator.Translate(Failure(result))));
        }
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new LdapException(81)));
        Assert.False(LdapConnectionProvider.IsConnectionFailure(new LdapException(87)));
        // A plain COM translation drops the cause; do not infer health from HRESULT alone.
        Assert.True(LdapConnectionProvider.IsConnectionFailure(LdapExceptionTranslator.Translate(new LdapException(87))));
        Assert.False(LdapConnectionProvider.IsConnectionFailure(new ArgumentException("filter", "Filter", new LdapException(87))));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new ArgumentException("unknown")));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new ArgumentException("transport", new LdapException(81))));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new LdapException(82)));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new LdapException(85)));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new LdapException(999)));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(Failure(ResultCode.Unavailable)));
        Assert.True(LdapConnectionProvider.IsConnectionFailure(new OperationCanceledException()));
    }

    [Fact]
    public void Key_preserves_exact_utf16_in_credentials_and_endpoint()
    {
        var values = new[] { "\uD800", "\uD801", "\uFFFD", "\uDC00", "\uD800\uDC00" };
        foreach (var field in new[] { "host", "user", "password" })
        {
            var keys = values.Select(value => LdapConnectionProvider.ConnectionKey.Create(new()
            {
                Host = field == "host" ? value : "directory.example",
                BindDn = field == "user" ? value : "reader",
                BindPassword = field == "password" ? value : "test password",
            }, ReferralChasingOption.None)).ToArray();
            Assert.Equal(values.Length, keys.Distinct().Count());
        }
    }

    [Fact]
    public void Per_key_saturation_does_not_evict_unrelated_idle_capacity()
    {
        using var pool = Pool(perKey: 1, total: 2, timeout: TimeSpan.FromMilliseconds(30));
        using var active = pool.Acquire("A", () => new Resource());
        var idleLease = pool.Acquire("B", () => new Resource()); var idle = idleLease.Value; idleLease.Dispose();
        Assert.Throws<TimeoutException>(() => pool.Acquire("A", () => throw new Exception("Per-key cap exceeded")));
        Assert.Equal(0, idle.Disposals);
        using var reused = pool.Acquire("B", () => throw new Exception("Unrelated idle connection was evicted"));
        Assert.Same(idle, reused.Value);
    }

    [Fact]
    public void Batch_larger_than_capacity_fails_before_creating_or_reserving()
    {
        using var pool = Pool(perKey: 1, total: 2);
        Assert.Throws<InvalidOperationException>(() => pool.AcquireBatch("directory", 2, () => throw new Exception("Unexpected creation")));
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public async Task Batch_waits_without_holding_partial_capacity()
    {
        using var pool = Pool(perKey: 2, total: 2);
        var active = pool.Acquire("directory", () => new Resource());
        var batch = Start(() => pool.AcquireBatch("directory", 2, () => new Resource()));
        Until(() => pool.Snapshot.Waiting == 1);
        Assert.Equal(1, pool.Snapshot.Total);
        active.Dispose();
        var leases = await batch.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.NotSame(leases[0].Value, leases[1].Value);
        Assert.Equal(2, pool.Snapshot.Total);
        foreach (var lease in leases) lease.Dispose();
    }

    [Fact]
    public void Partial_batch_initialization_failure_cleans_all_reserved_capacity()
    {
        using var pool = Pool(perKey: 2, total: 2);
        var first = new Resource(); var creations = 0;
        Assert.Throws<InvalidOperationException>(() => pool.AcquireBatch("directory", 2, () =>
            ++creations == 1 ? first : throw new InvalidOperationException("Bind failed")));
        Assert.Equal(1, first.Disposals); Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public void Fresh_checkout_reclaims_same_key_idle_and_rejects_late_old_returns()
    {
        using var pool = Pool(perKey: 2, total: 2);
        var old = pool.Acquire("directory", () => new Resource()); var oldValue = old.Value;
        var idle = pool.Acquire("directory", () => new Resource()); var idleValue = idle.Value; idle.Dispose();
        var generation = pool.NewGeneration();
        var fresh = pool.Acquire("directory", () => new Resource(), preferFresh: true, minimumGeneration: generation);
        var freshValue = fresh.Value;
        Assert.Equal(1, idleValue.Disposals); Assert.Equal(0, oldValue.Disposals);
        fresh.Dispose(); old.Dispose();
        using var next = pool.Acquire("directory", () => throw new Exception("Eligible fresh connection was lost"), minimumGeneration: generation);
        Assert.Same(freshValue, next.Value); Assert.Equal(1, oldValue.Disposals);
    }
    [Fact]
    public async Task Opposite_endpoint_order_never_holds_partial_capacity()
    {
        using var pool = Pool(perKey: 1, total: 2);
        using var start = new ManualResetEventSlim();
        var tasks = Enumerable.Range(0, 12).Select(worker => Start(() =>
        {
            start.Wait();
            for (var round = 0; round < 40; round++)
            {
                var keys = worker % 2 == 0 ? new[] { "source", "destination" } : new[] { "destination", "source" };
                var pair = pool.AcquireMany(keys.Select(key => new BoundedConnectionPool<string, Resource>.Request(key, () => new Resource())).ToArray());
                foreach (var lease in pair) Assert.Equal(1, Interlocked.Increment(ref lease.Value.Users));
                foreach (var lease in pair) { Assert.Equal(0, Interlocked.Decrement(ref lease.Value.Users)); lease.Dispose(); }
            }
            return true;
        })).ToArray();
        start.Set(); await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Equal(2, pool.Snapshot.Total); Assert.Equal(2, pool.Snapshot.Created);
    }

    [Fact]
    public void Pair_second_bind_failure_disposes_reused_first_endpoint()
    {
        using var pool = Pool(perKey: 1, total: 2);
        var first = pool.Acquire("source", () => new Resource()); var value = first.Value; first.Dispose();
        Assert.Throws<InvalidOperationException>(() => pool.AcquireMany([
            new("source", () => throw new Exception("Expected reuse")),
            new("destination", () => throw new InvalidOperationException("Bind failed"))]));
        Assert.Equal(1, value.Disposals); Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Keys);
    }

    [Fact]
    public async Task Cancelled_pair_waiter_does_not_reserve_other_endpoint()
    {
        using var pool = Pool(perKey: 1, total: 2);
        using var source = pool.Acquire("source", () => new Resource());
        using var cancel = new CancellationTokenSource();
        var waiting = Start(() => Assert.Throws<OperationCanceledException>(() => pool.AcquireMany([
            new("destination", () => throw new Exception("No partial reservation")),
            new("source", () => throw new Exception("Source still occupied"))], cancel.Token)));
        Until(() => pool.Snapshot.Waiting == 1);
        Assert.Equal(1, pool.Snapshot.Total); Assert.Equal(1, pool.Snapshot.Keys);
        cancel.Cancel(); await waiting.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(0, pool.Snapshot.Waiting);
    }

}
