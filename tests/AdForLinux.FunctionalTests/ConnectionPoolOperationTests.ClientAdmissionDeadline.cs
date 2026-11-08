using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class AdmissionDeadlineClock : TimeProvider
    {
        private readonly object gate = new();
        private long ticks;
        private readonly List<DeadlineTimer> timers = [];
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() { lock (gate) return ticks; }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new DeadlineTimer(this, callback, state);
            lock (gate) timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        internal void Advance(TimeSpan elapsed)
        {
            DeadlineTimer[] due;
            lock (gate)
            {
                ticks += elapsed.Ticks;
                due = timers.Where(timer => !timer.Disposed && timer.Due <= ticks).ToArray();
                foreach (var timer in due) timer.Due = long.MaxValue;
            }
            foreach (var timer in due) timer.Callback(timer.State);
        }
        private sealed class DeadlineTimer(AdmissionDeadlineClock clock, TimerCallback callback, object? state) : ITimer
        {
            internal readonly TimerCallback Callback = callback;
            internal readonly object? State = state;
            internal long Due = long.MaxValue;
            internal bool Disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                if (period != Timeout.InfiniteTimeSpan) throw new NotSupportedException("Only cancellation's one-shot timer is used.");
                lock (clock.gate)
                {
                    if (Disposed) return false;
                    Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : checked(clock.ticks + dueTime.Ticks);
                    return true;
                }
            }
            public void Dispose() { lock (clock.gate) { Disposed = true; clock.timers.Remove(this); } }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    [Theory]
    [InlineData("FindOne")]
    [InlineData("cached FindAll")]
    [InlineData("streaming FindAll")]
    public async Task Neutral_client_deadline_must_bound_waiting_for_a_held_session_group_regression(string operation)
    {
        var clock = new AdmissionDeadlineClock();
        using var cleanup = new CancellationTokenSource();
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2,
            acquisitionTimeout: TimeSpan.FromSeconds(10), startTimer: false);
        using var root = new DirectoryEntry("LDAP://offline.invalid/DC=example,DC=test");
        root.Options.Referral = ReferralChasingOption.None;
        var trace = new List<string>();
        var transports = new List<ConversationTransport>();
        var admissionBudgets = new List<TimeSpan>();
        BoundLdapSession Create(LdapConnectionOptions options, ReferralChasingOption referrals)
        {
            var transport = new ConversationTransport(trace);
            transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false));
            transports.Add(transport);
            return new BoundLdapSession(transport, transport, options, new(options), referrals);
        }
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
        {
            admissionBudgets.Add(options.Timeout);
            // Model the admitted boundary's recipe timeout. A propagated shorter
            // client budget would cancel this real pool wait on clock.Advance.
            using var recipeDeadline = new CancellationTokenSource(options.Timeout, clock);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cleanup.Token, recipeDeadline.Token);
            try
            {
                return pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count,
                    () => Create(options, referrals), cancellation.Token, reusable: false)
                    .Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            }
            catch (OperationCanceledException) when (!cleanup.IsCancellationRequested)
            { throw new TimeoutException("Admission budget expired before a session was available."); }
        };

        // Resolve the root before the measured query so this case isolates the
        // query/session admission gap, rather than initial object validation.
        root.BindEntry();
        var options = root.BuildOptions();
        var held = pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None), 2,
            () => Create(options, ReferralChasingOption.None), reusable: false);
        using var searcher = new DirectorySearcher(root)
        {
            CacheResults = operation != "streaming FindAll",
            ClientTimeout = TimeSpan.FromMilliseconds(100),
            TimeProvider = clock,
            ReferralChasing = ReferralChasingOption.None,
        };
        using var clientDeadlineCanary = new CancellationTokenSource(searcher.ClientTimeout, clock);
        var pending = Task.Factory.StartNew(() => Record.Exception(() =>
        {
            if (operation == "FindOne") _ = searcher.FindOne();
            else { using var results = searcher.FindAll(); _ = results.Count; }
        }), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        bool completedBeforeRelease = false;
        Exception? failure = null;
        try
        {
            Assert.True(SpinWait.SpinUntil(() => pool.Snapshot.Waiting == 1, TimeSpan.FromSeconds(5)), "The query did not enter the held pool wait.");
            clock.Advance(TimeSpan.FromSeconds(1)); // ten times the configured client deadline
            Assert.True(clientDeadlineCanary.IsCancellationRequested, "The controlled clock must deliver a timer at the client deadline.");
            // This is a generous test-runner scheduling bound, not the simulated
            // client deadline. Capacity remains held throughout the observation.
            completedBeforeRelease = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(1))) == pending;
        }
        finally
        {
            foreach (var lease in held) lease.Dispose();
            try { failure = await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (TimeoutException)
            {
                cleanup.Cancel();
                failure = await pending.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }

        Assert.IsType<TimeoutException>(failure);
        Assert.Equal(0, pool.Snapshot.Waiting);
        Assert.Equal(0, pool.Snapshot.Total);
        Assert.Equal(1, trace.Count(item => item == "buffered-search")); // only pre-bound root validation
        Assert.Equal(0, trace.Count(item => item == "open")); // no application send after late admission
        Assert.Equal(transports.Count, trace.Count(item => item == "session-close"));
        Assert.Equal(2, admissionBudgets.Count);
        Assert.True(completedBeforeRelease,
            $"{operation} remained blocked after ClientTimeout elapsed; admission received recipe timeout {admissionBudgets[1]} instead of the 100ms client budget. No late query was sent after capacity release.");
    }
}
