using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class CredentialClock : TimeProvider
    {
        internal long Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
        internal void Advance(int seconds) => Ticks += TimeSpan.FromSeconds(seconds).Ticks;
    }
    private sealed class RecordingWorker : LdapRestrictedOperation.IManagedWorker
    {
        internal readonly RecordingTransport[] Transports;
        internal int Disposals;
        internal RecordingWorker(int count) => Transports = Enumerable.Range(0, count).Select(_ => new RecordingTransport()).ToArray();
        public IReadOnlyList<ILdapRequestTransport> Sessions => Transports;
        public uint CredentialLifetimeSeconds { get; set; } = 120;
        public bool Healthy => Disposals == 0;
        public void Dispose() { Disposals++; foreach (var transport in Transports) transport.Dispose(); }
    }
    private sealed class ManagedFixture : IDisposable
    {
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, LdapRestrictedOperation.ManagedWorker> Pool;
        internal readonly List<RecordingWorker> Workers = [];
        internal Action<LdapWorkerStart>? Creating;
        internal ManagedFixture(int capacity = 2) => Pool = new(capacity, capacity, startTimer: false,
            acquisitionTimeout: TimeSpan.FromSeconds(2), generationSource: LdapConnectionProvider.NewGeneration);
        internal LdapConnectionProvider.Session[] Open(LdapConnectionOptions options, int count, ReferralChasingOption referrals,
            bool fresh = false, long minimum = 0, CancellationToken token = default)
            => LdapRestrictedOperation.AcquireWorkerGroupCore(options, count, referrals, () => TimeSpan.FromSeconds(2), token, Pool,
                (start, _, cancellation) =>
                {
                    cancellation.ThrowIfCancellationRequested(); Creating?.Invoke(start);
                    var worker = new RecordingWorker(start.SessionCount); Workers.Add(worker); return worker;
                }, fresh, minimum);
        internal DirectoryEntry Entry(KerberosCredentialContext context)
        {
            var profile = new RestrictedKerberosProfile(Path.GetFullPath("/nonexistent-adfl-bundle/version-1"), context,
                "EXAMPLE.INVALID", "directory.invalid", 389, "kdc.invalid");
            var entry = profile.CreateDirectoryEntry("");
            entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) => Open(options, count, referrals, fresh, minimum);
            return entry;
        }
        public void Dispose() => Pool.Dispose();
    }

    [Fact]
    public async Task Owned_cache_bytes_and_retention_callback_never_enter_json_protocol()
    {
        var start = new LdapWorkerStart("offline.invalid", 389, false, true, true, 1,
            TimeSpan.FromSeconds(5), new(LdapCredentialSourceKind.Owned, "/proc/self/fd/6"))
            with { OwnedCache = new byte[1048576], RetainOwnedCache = () => throw new InvalidOperationException() };
        using var channel = new MemoryStream();
        await LdapWorkerProtocol.WriteAsync(channel, LdapWorkerProtocol.Frame(1, 0, "START", start.Timeout, start), default);
        Assert.True(channel.Length < 4096);
        channel.Position = 0;
        var copy = LdapWorkerProtocol.Payload<LdapWorkerStart>(await LdapWorkerProtocol.ReadAsync(channel, default));
        Assert.Null(copy.OwnedCache); Assert.Null(copy.RetainOwnedCache);
        Assert.Equal(start.CredentialSource, copy.CredentialSource);
    }

    [Fact]
    public void Managed_public_operations_reuse_whole_groups_and_close_requires_new_binding()
    {
        using var context = new KerberosCredentialContext([1, 2, 3]); // recording material, not a native cache
        using var fixture = new ManagedFixture(); using var entry = fixture.Entry(context);
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        Assert.Single(fixture.Workers); Assert.Equal(2, fixture.Workers[0].Transports[0].Sends);
        Assert.Equal(1, fixture.Pool.Snapshot.Reused);
        entry.Close();
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        Assert.Equal(2, fixture.Workers.Count); Assert.Equal(1, fixture.Workers[0].Disposals);
    }

    [Fact]
    public void Publication_retires_idle_groups_but_allows_admitted_old_operation_to_finish()
    {
        using var context = new KerberosCredentialContext([1]);
        using var fixture = new ManagedFixture(); using var entry = fixture.Entry(context);
        using var old = entry.AcquireConnection();
        context.Publish([2]);
        Assert.Equal(0, fixture.Workers[0].Disposals);
        Assert.Equal("observed-dc.invalid", old.ExecuteTransport(RootDse.GetConnectedServerName));
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        Assert.Equal(2, fixture.Workers.Count);
        old.Dispose(); Assert.Equal(1, fixture.Workers[0].Disposals);
        context.Publish([3]); Assert.Equal(1, fixture.Workers[1].Disposals);
        Assert.Equal(0, fixture.Pool.Snapshot.Total);
    }

    [Fact]
    public void Publication_during_creation_discards_stale_binding_before_application_dispatch()
    {
        using var context = new KerberosCredentialContext([1]);
        using var fixture = new ManagedFixture(); using var entry = fixture.Entry(context);
        var calls = 0;
        fixture.Creating = start =>
        {
            Assert.Equal(LdapCredentialSourceKind.Owned, start.CredentialSource!.Kind);
            Assert.Equal(++calls, start.OwnedCache![0]);
            if (calls == 1) context.Publish([2]);
        };
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        Assert.Equal(2, fixture.Workers.Count);
        Assert.Equal(0, fixture.Workers[0].Transports[0].Sends);
        Assert.Equal(1, fixture.Workers[0].Disposals);
        Assert.Equal(1, fixture.Workers[1].Transports[0].Sends);
    }

    [Fact]
    public void Owned_snapshot_copy_and_detached_startup_lifetime_survive_publication()
    {
        byte[] original = [1, 2, 3];
        using var context = new KerberosCredentialContext(original);
        var generation = context.Capture();
        original[0] = 9; Assert.Equal(1, generation.Bytes[0]);
        using var startup = generation.RetainStartup();
        context.Publish([4]);
        Assert.False(context.Admit(generation));
        generation.Dispose();
        Assert.Equal(1, generation.Bytes[0]);
        startup.Dispose(); Assert.All(generation.Bytes, value => Assert.Equal(0, value));
    }

    [Fact]
    public void Expired_owned_credentials_refuse_checkout_without_another_bind()
    {
        var clock = new CredentialClock();
        using var context = new KerberosCredentialContext([1], clock);
        using var fixture = new ManagedFixture(); using var entry = fixture.Entry(context);
        _ = entry.Options.GetCurrentServerName();
        clock.Advance(116);
        Assert.Throws<InvalidOperationException>(() => entry.Options.GetCurrentServerName());
        Assert.Single(fixture.Workers);
        context.Publish([2]); _ = entry.Options.GetCurrentServerName();
        Assert.Equal(2, fixture.Workers.Count);
    }

    [Fact]
    public void Managed_group_fault_retires_both_members_and_does_not_replay()
    {
        using var context = new KerberosCredentialContext([1]);
        using var fixture = new ManagedFixture(); using var entry = fixture.Entry(context);
        var sessions = fixture.Open(entry.BuildOptions(), 2, ReferralChasingOption.None);
        var failure = new IOException("synthetic transport failure");
        fixture.Workers[0].Transports[0].Reply = _ => throw failure;
        Assert.Same(failure, Assert.Throws<IOException>(() => sessions[0].ExecuteTransport(RootDse.GetConnectedServerName)));
        Assert.Throws<ObjectDisposedException>(() => sessions[1].ExecuteTransport(RootDse.GetConnectedServerName));
        foreach (var session in sessions) session.Dispose();
        Assert.Equal(1, fixture.Workers[0].Disposals);
        Assert.Equal(1, fixture.Workers[0].Transports.Sum(t => t.Sends));
        Assert.Equal(0, fixture.Pool.Snapshot.Total);
    }

    [Fact]
    public void Shared_group_admission_evicts_idle_managed_worker_for_fresh_external_source()
    {
        using var context = new KerberosCredentialContext([1]);
        using var fixture = new ManagedFixture(1); using var entry = fixture.Entry(context);
        _ = entry.Options.GetCurrentServerName();
        using var fresh = RestrictedRecipe().CreateDirectoryEntry("");
        fixture.Creating = _ => Assert.Equal(1, fixture.Workers[0].Disposals);
        var session = fixture.Open(fresh.BuildOptions(), 1, ReferralChasingOption.None)[0];
        session.Dispose(); Assert.All(fixture.Workers, worker => Assert.Equal(1, worker.Disposals));
        Assert.Equal(0, fixture.Pool.Snapshot.Total);
    }

    [Fact]
    public void Physical_pressure_evicts_only_idle_groups_even_below_logical_limit()
    {
        using var first = new KerberosCredentialContext([1]);
        using var second = new KerberosCredentialContext([2]);
        using var third = new KerberosCredentialContext([3]);
        using var fixture = new ManagedFixture(3);
        using var a = fixture.Entry(first); using var b = fixture.Entry(second); using var c = fixture.Entry(third);
        using var held = a.AcquireConnection();
        _ = b.Options.GetCurrentServerName();
        fixture.Creating = _ =>
        {
            // Models one unreaped process occupying physical capacity while the
            // logical pool can still reserve its third slot.
            Assert.True(fixture.Pool.EvictOneIdle());
            Assert.Equal(0, fixture.Workers[0].Disposals);
            Assert.Equal(1, fixture.Workers[1].Disposals);
            Assert.False(fixture.Pool.EvictOneIdle());
        };
        _ = c.Options.GetCurrentServerName();
        Assert.Equal(3, fixture.Workers.Count);
    }

    [Fact]
    public void Retirement_registry_tracks_live_groups_not_historical_recipe_keys()
    {
        using var context = new KerberosCredentialContext([1]);
        using var generation = context.Capture();
        using var fixture = new ManagedFixture(1); using var entry = fixture.Entry(context);
        for (var i = 1; i <= 256; i++)
        {
            var sessions = fixture.Open(entry.BuildOptions().Clone(TimeSpan.FromSeconds(i)), 1, ReferralChasingOption.None);
            sessions[0].Dispose();
            Assert.Equal(1, fixture.Pool.Snapshot.Keys);
            Assert.Equal(1, generation.RegistrationCount);
        }
        fixture.Pool.Dispose();
        Assert.Equal(0, generation.RegistrationCount);
    }

    [Fact]
    public void Failed_and_cancelled_creation_release_retirement_registration()
    {
        using var context = new KerberosCredentialContext([1]);
        using var generation = context.Capture();
        using var fixture = new ManagedFixture(1); using var entry = fixture.Entry(context);
        fixture.Creating = _ => throw new IOException("recorded creation failure");
        Assert.Throws<IOException>(() => fixture.Open(entry.BuildOptions(), 1, ReferralChasingOption.None));
        Assert.Equal(0, generation.RegistrationCount);
        fixture.Creating = null;
        using var held = entry.AcquireConnection();
        Assert.Throws<OperationCanceledException>(() => fixture.Open(entry.BuildOptions().Clone(TimeSpan.FromSeconds(17)),
            1, ReferralChasingOption.None, token: new CancellationToken(true)));
        Assert.Equal(1, generation.RegistrationCount);
        context.Publish([2]);
        held.Dispose();
        Assert.Equal(0, generation.RegistrationCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Physical_capacity_timeout_or_cancellation_never_releases_unacquired_slot(bool cancel)
    {
        using var physical = new SemaphoreSlim(0, 1);
        using var cancellation = new CancellationTokenSource();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var pending = NativeLdapWorkerPool.WaitForCapacityAsync(physical,
            () => TimeSpan.FromMilliseconds(150) - timer.Elapsed,
            () => { if (cancel) cancellation.Cancel(); }, cancellation.Token);
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        else await Assert.ThrowsAsync<TimeoutException>(() => pending);
        Assert.Equal(0, physical.CurrentCount);
        physical.Release();
        Assert.Equal(1, physical.CurrentCount);
    }

    [Fact]
    public async Task Physical_capacity_wait_rechecks_groups_returned_idle_after_initial_pressure()
    {
        using var first = new KerberosCredentialContext([1]);
        using var second = new KerberosCredentialContext([2]);
        using var fixture = new ManagedFixture(3);
        using var a = fixture.Entry(first); using var b = fixture.Entry(second);
        using var held = a.AcquireConnection(); using var returning = b.AcquireConnection();
        // Two active workers plus an unreaped worker occupy all physical slots.
        using var physical = new SemaphoreSlim(0, 3);
        using var cancellation = new CancellationTokenSource();
        var initial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var evicted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var pending = NativeLdapWorkerPool.WaitForCapacityAsync(physical,
            () => TimeSpan.FromSeconds(2) - timer.Elapsed,
            () => { if (fixture.Pool.EvictOneIdle()) evicted.TrySetResult(); else initial.TrySetResult(); }, cancellation.Token);
        try
        {
            await initial.Task.WaitAsync(TimeSpan.FromSeconds(1));
            returning.Dispose();
            await evicted.Task.WaitAsync(TimeSpan.FromSeconds(1));
            Assert.False(pending.IsCompleted); // Retirement alone does not release capacity.
            Assert.Equal(0, fixture.Workers[0].Disposals);
            Assert.Equal(1, fixture.Workers[1].Disposals);
            physical.Release(); // Models the verified process-exit callback only.
            await pending;
            Assert.Equal(0, physical.CurrentCount);
        }
        finally
        {
            cancellation.Cancel();
            try { await pending; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public void Different_managers_never_share_a_group_and_cancelled_wait_does_not_create()
    {
        using var first = new KerberosCredentialContext([1]); using var second = new KerberosCredentialContext([1]);
        using var fixture = new ManagedFixture(1); using var a = fixture.Entry(first); using var b = fixture.Entry(second);
        using var held = a.AcquireConnection();
        Assert.Throws<OperationCanceledException>(() => fixture.Open(b.BuildOptions(), 1, ReferralChasingOption.None,
            token: new CancellationToken(true)));
        Assert.Single(fixture.Workers);
        held.Dispose(); _ = b.Options.GetCurrentServerName();
        Assert.Equal(2, fixture.Workers.Count); Assert.Equal(1, fixture.Workers[0].Disposals);
    }
}
