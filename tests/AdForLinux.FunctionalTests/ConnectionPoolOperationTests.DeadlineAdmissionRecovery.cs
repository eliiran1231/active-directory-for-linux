using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class DeadlineWorker : LdapRestrictedOperation.IManagedWorker
    {
        internal readonly ConversationTransport[] Transports;
        internal int Disposals;
        internal bool ThrowOnDispose;
        internal Action? SessionsRead;
        internal DeadlineWorker(int count, List<string> trace)
        {
            Transports = Enumerable.Range(0, count).Select(_ =>
            {
                var transport = new ConversationTransport(trace);
                transport.OnOpen = _ => transport.Events = new([
                    new LdapSearchEvent.PageEnd(Envelope(System.DirectoryServices.Protocols.ResultCode.Success), false)]);
                return transport;
            }).ToArray();
        }
        public IReadOnlyList<ILdapRequestTransport> Sessions { get { SessionsRead?.Invoke(); return Transports; } }
        public uint CredentialLifetimeSeconds => 120;
        public bool Healthy => Disposals == 0;
        public void Dispose()
        {
            Disposals++; foreach (var transport in Transports) transport.Dispose();
            if (ThrowOnDispose) throw new IOException("Controlled worker disposal failure.");
        }
    }

    private sealed class DeadlineAdmissionFixture : IDisposable
    {
        internal static readonly TimeSpan ClientBudget = TimeSpan.FromMilliseconds(10125);
        internal readonly AdmissionDeadlineClock Clock = new();
        internal readonly DirectoryEntry Root;
        internal readonly List<DeadlineWorker> Workers = [];
        internal readonly List<string> Trace = [];
        internal readonly List<LdapConnectionProvider.ConnectionKey> Keys = [];
        internal readonly List<TimeSpan> StartupBudgets = [];
        internal readonly List<LdapConnectionProvider.Session[]> ReturnedBatches = [];
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, LdapRestrictedOperation.ManagedWorker> Pool =
            new(1, 1, acquisitionTimeout: TimeSpan.FromSeconds(5), startTimer: false,
                generationSource: LdapConnectionProvider.NewGeneration);
        private readonly KerberosCredentialContext? credentials;
        internal Action<LdapWorkerStart, TimeSpan, CancellationToken>? Creating;
        internal Action? Returned;
        internal Exception? AdmissionError;
        internal int MeasuredAdmissions;
        internal CancellationToken AdmissionToken;

        internal DeadlineAdmissionFixture(bool reusable = false)
        {
            if (reusable) credentials = new KerberosCredentialContext([1, 2, 3]); // recording material only
            var profile = credentials is null ? RestrictedRecipe() : new RestrictedKerberosProfile(
                Path.GetFullPath("/nonexistent-adfl-bundle/version-1"), credentials,
                "EXAMPLE.INVALID", "directory.invalid", 389, "kdc.invalid");
            Root = profile.CreateDirectoryEntry("DC=example");
            Root.OperationSessionFactoryWithBudget = (options, count, referrals, fresh, minimum, remaining, token) =>
            {
                Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
                if (remaining is not null)
                {
                    MeasuredAdmissions++;
                    AdmissionToken = token;
                    if (AdmissionError is not null) throw AdmissionError;
                }
                var sessions = Open(options, count, referrals, remaining, token, fresh, minimum);
                ReturnedBatches.Add(sessions);
                if (remaining is not null) Returned?.Invoke();
                return sessions;
            };
            Root.BindEntry(); // initial root validation remains outside the search deadline
        }
        internal LdapConnectionProvider.Session[] Open(LdapConnectionOptions options, int count,
            ReferralChasingOption referrals, Func<TimeSpan>? remaining = null, CancellationToken token = default,
            bool fresh = false, long minimum = 0)
        {
            Keys.Add(LdapConnectionProvider.ConnectionKey.Create(options, referrals));
            // Production Restricted.Acquire supplies a minimum of the recipe's
            // elapsed admission limit and the external search deadline to Core.
            // Model that caller contract with the controlled clock as well.
            var started = Clock.GetTimestamp();
            TimeSpan AdmissionRemaining()
            {
                token.ThrowIfCancellationRequested();
                var left = options.Timeout - Clock.GetElapsedTime(started);
                if (remaining is not null)
                {
                    var searchLeft = remaining();
                    if (searchLeft < left) left = searchLeft;
                }
                return left > TimeSpan.Zero ? left : throw new TimeoutException("Controlled admission budget expired.");
            }
            return LdapRestrictedOperation.AcquireWorkerGroupCore(options, count, referrals,
                AdmissionRemaining, token, Pool, (start, timeout, cancellation) =>
                {
                    var worker = new DeadlineWorker(start.SessionCount, Trace);
                    Workers.Add(worker);
                    try
                    {
                        if (remaining is not null)
                        {
                            StartupBudgets.Add(timeout);
                            Creating?.Invoke(start, timeout, cancellation);
                        }
                        return worker;
                    }
                    catch { worker.Dispose(); throw; }
                }, fresh, minimum);
        }
        internal DirectorySearcher Searcher(string mode, TimeSpan? timeout = null) => new(Root)
        {
            CacheResults = mode != "streaming FindAll",
            Asynchronous = mode.StartsWith("async", StringComparison.Ordinal),
            PageSize = mode.Contains("paged", StringComparison.Ordinal) ? 1 : 0,
            SizeLimit = mode.Contains("paged", StringComparison.Ordinal) ? 2 : 0,
            ReferralChasing = ReferralChasingOption.None,
            ClientTimeout = timeout ?? ClientBudget,
            TimeProvider = Clock,
        };
        internal static void Execute(DirectorySearcher searcher, string mode)
        {
            if (mode == "FindOne") Assert.Null(searcher.FindOne());
            else { using var rows = searcher.FindAll(); Assert.Empty(rows.Cast<SearchResult>()); }
        }
        internal void AssertReleased()
        {
            Assert.Equal(0, Pool.Snapshot.Total); Assert.Equal(0, Pool.Snapshot.Waiting);
            Assert.All(Workers, worker => Assert.Equal(1, worker.Disposals));
            Assert.Equal(Workers.Sum(worker => worker.Transports.Length), Trace.Count(value => value == "session-close"));
            Assert.All(Keys, key => Assert.Equal(Keys[0], key));
        }
        public void Dispose() { Root.Dispose(); Pool.Dispose(); credentials?.Dispose(); }
    }

    [Theory]
    [MemberData(nameof(SharedBudgetModes))]
    public void Expired_neutral_deadline_refuses_before_measured_admission(string mode)
    {
        using var fixture = new DeadlineAdmissionFixture();
        using var searcher = fixture.Searcher(mode, TimeSpan.Zero);
        Assert.Throws<TimeoutException>(() => DeadlineAdmissionFixture.Execute(searcher, mode));
        Assert.Equal(0, fixture.MeasuredAdmissions);
        Assert.Single(fixture.Workers); Assert.DoesNotContain("open", fixture.Trace);
        fixture.AssertReleased();
    }

    [Theory]
    [InlineData("FindOne")]
    [InlineData("streaming FindAll")]
    [InlineData("async paged FindAll")]
    public async Task Public_neutral_deadline_cancels_held_managed_group_then_admits_a_fresh_search(string mode)
    {
        using var fixture = new DeadlineAdmissionFixture();
        var held = fixture.Open(fixture.Root.BuildOptions(), 2, ReferralChasingOption.None);
        using var searcher = fixture.Searcher(mode);
        var pending = Task.Factory.StartNew(() => Record.Exception(() => DeadlineAdmissionFixture.Execute(searcher, mode)),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            Assert.True(SpinWait.SpinUntil(() => fixture.Pool.Snapshot.Waiting == 1, TimeSpan.FromSeconds(5)));
            fixture.Clock.Advance(TimeSpan.FromSeconds(11));
            Assert.IsType<TimeoutException>(await pending.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Equal(1, fixture.Pool.Snapshot.Total); // held group is still owned
            Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
            Assert.Equal(2, fixture.Workers.Count); Assert.DoesNotContain("open", fixture.Trace);
        }
        finally { foreach (var session in held) session.Dispose(); await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
        fixture.AssertReleased();
        DeadlineAdmissionFixture.Execute(searcher, mode);
        Assert.Equal(1, fixture.Trace.Count(value => value == "open"));
        fixture.AssertReleased();
    }

    [Theory]
    [InlineData("FindOne")]
    [InlineData("streaming FindAll")]
    public async Task Capacity_release_then_deadline_during_startup_closes_late_group_without_publication(string mode)
    {
        using var fixture = new DeadlineAdmissionFixture();
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        CancellationToken startupToken = default;
        fixture.Creating = (start, timeout, token) =>
        {
            Assert.Equal(TimeSpan.FromSeconds(11), start.Timeout); // wire rounds up, client wait must not
            Assert.Equal(DeadlineAdmissionFixture.ClientBudget, timeout);
            startupToken = token; entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(5)));
        };
        var held = fixture.Open(fixture.Root.BuildOptions(), 2, ReferralChasingOption.None);
        using var searcher = fixture.Searcher(mode);
        var pending = Task.Factory.StartNew(() => Record.Exception(() => DeadlineAdmissionFixture.Execute(searcher, mode)),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Exception? failure = null;
        try
        {
            Assert.True(SpinWait.SpinUntil(() => fixture.Pool.Snapshot.Waiting == 1, TimeSpan.FromSeconds(5)));
            foreach (var session in held) session.Dispose(); // capacity wins before the deadline
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            fixture.Clock.Advance(TimeSpan.FromSeconds(11));
            Assert.True(startupToken.IsCancellationRequested);
            Assert.False(pending.IsCompleted); // this synthetic startup returns only when explicitly released
            Assert.Equal(1, fixture.Pool.Snapshot.Total);
            Assert.Equal(0, fixture.Workers[2].Disposals); Assert.DoesNotContain("open", fixture.Trace);
        }
        finally
        {
            release.Set(); foreach (var session in held) session.Dispose();
            failure = await pending.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Assert.IsType<TimeoutException>(failure);
        Assert.Equal(3, fixture.Workers.Count); fixture.AssertReleased();
    }

    [Theory]
    [InlineData("FindOne")]
    [InlineData("streaming FindAll")]
    public void Expiry_after_group_admission_but_before_entry_publication_closes_every_session(string mode)
    {
        using var fixture = new DeadlineAdmissionFixture();
        fixture.Returned = () => fixture.Clock.Advance(TimeSpan.FromSeconds(11));
        using var searcher = fixture.Searcher(mode);
        Assert.Throws<TimeoutException>(() => DeadlineAdmissionFixture.Execute(searcher, mode));
        Assert.Equal(2, fixture.Workers.Count); Assert.DoesNotContain("open", fixture.Trace);
        fixture.AssertReleased();
        fixture.Returned = null;
        DeadlineAdmissionFixture.Execute(searcher, mode);
        Assert.Equal(1, fixture.Trace.Count(value => value == "open")); fixture.AssertReleased();
    }

    [Fact]
    public void Unrelated_admission_cancellation_is_not_relabelled_as_search_timeout()
    {
        using var fixture = new DeadlineAdmissionFixture();
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        var original = new OperationCanceledException(cancellation.Token);
        fixture.AdmissionError = original;
        using var searcher = fixture.Searcher("FindOne");
        Assert.Same(original, Assert.Throws<OperationCanceledException>(() => searcher.FindOne()));
        fixture.AssertReleased();
    }

    [Fact]
    public void Different_client_deadlines_reuse_the_same_healthy_managed_group_and_immutable_recipe()
    {
        using var fixture = new DeadlineAdmissionFixture(reusable: true);
        using var searcher = fixture.Searcher("FindOne", TimeSpan.FromSeconds(2));
        DeadlineAdmissionFixture.Execute(searcher, "FindOne");
        searcher.ClientTimeout = TimeSpan.FromSeconds(20);
        DeadlineAdmissionFixture.Execute(searcher, "FindOne");
        searcher.ClientTimeout = TimeSpan.FromSeconds(int.MaxValue);
        DeadlineAdmissionFixture.Execute(searcher, "FindOne");
        Assert.Single(fixture.Workers);
        Assert.Equal(3, fixture.Trace.Count(value => value == "open"));
        Assert.Equal(3, fixture.Pool.Snapshot.Reused); // root validation plus three searches use one worker
        Assert.All(fixture.Keys, key => Assert.Equal(fixture.Keys[0], key));
        Assert.Equal(TimeSpan.FromSeconds(30), fixture.Root.BuildOptions().Timeout);
        fixture.Pool.Dispose(); fixture.AssertReleased();
    }

    [Fact]
    public void Deadline_after_first_session_creation_releases_partial_batch_and_allows_atomic_retry()
    {
        var clock = new AdmissionDeadlineClock();
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        using var root = RestrictedRecipe().CreateDirectoryEntry("DC=example");
        var trace = new List<string>(); var counts = new List<int>();
        var clones = new List<DirectoryEntry>(); var creations = 0; var expire = true;
        var key = LdapConnectionProvider.ConnectionKey.Create(root.BuildOptions(), ReferralChasingOption.None);
        root.OperationSessionFactoryWithBudget = (options, count, referrals, fresh, minimum, remaining, token) =>
        {
            Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
            Assert.Equal(key, LdapConnectionProvider.ConnectionKey.Create(options, referrals));
            counts.Add(count);
            return pool.AcquireBatch(key, count, () =>
            {
                creations++;
                var transport = new ConversationTransport(trace);
                transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(System.DirectoryServices.Protocols.ResultCode.Success), false));
                if (remaining is not null && expire) clock.Advance(TimeSpan.FromSeconds(11));
                return new BoundLdapSession(transport, transport, options, new(options), referrals);
            }, token, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        };
        root.BindEntry();
        using var searcher = new DirectorySearcher(root) { CacheResults = false,
            ClientTimeout = DeadlineAdmissionFixture.ClientBudget, TimeProvider = clock,
            ReferralChasing = ReferralChasingOption.None, StreamingRootCreated = clones.Add };
        Assert.Throws<TimeoutException>(() => searcher.FindAll());
        Assert.Equal(new[] { 1, 2 }, counts);
        Assert.Equal(2, creations); // root plus one partial member; second member never starts
        Assert.Equal(2, trace.Count(value => value == "session-close"));
        Assert.DoesNotContain("open", trace); Assert.True(Assert.Single(clones).IsDisposed);
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Waiting);
        expire = false;
        using (var repaired = searcher.FindAll()) Assert.Empty(repaired.Cast<SearchResult>());
        Assert.Equal(new[] { 1, 2, 2 }, counts); Assert.Equal(4, creations);
        Assert.Equal(4, trace.Count(value => value == "session-close"));
        Assert.Equal(1, trace.Count(value => value == "open"));
        Assert.All(clones, clone => Assert.True(clone.IsDisposed));
        Assert.Equal(0, pool.Snapshot.Total); Assert.Equal(0, pool.Snapshot.Waiting);
    }

    [Fact]
    public async Task Inner_admission_deadline_remains_timeout_when_outer_timer_has_not_fired()
    {
        using var fixture = new DeadlineAdmissionFixture();
        var held = fixture.Open(fixture.Root.BuildOptions(), 2, ReferralChasingOption.None);
        // Model scheduling/preparation between sampling Remaining() and arming
        // its relative timer. Core receives a fresher50ms budget and owns a real
        // timer; the deliberately later outer timer must not determine its type.
        fixture.Clock.BeforeTimerCreation = () => fixture.Clock.Advance(TimeSpan.FromMilliseconds(10075));
        using var searcher = fixture.Searcher("FindOne");
        var pending = Task.Factory.StartNew(() => Record.Exception(() => searcher.FindOne()),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Exception? failure;
        try
        {
            failure = await pending.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(fixture.AdmissionToken.IsCancellationRequested);
            Assert.Equal(1, fixture.Pool.Snapshot.Total); // independent held group
            Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
            Assert.DoesNotContain("open", fixture.Trace);
        }
        finally { foreach (var session in held) session.Dispose(); await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
        fixture.AssertReleased();
        Assert.IsType<TimeoutException>(failure);
    }

    [Theory]
    [InlineData("FindOne")]
    [InlineData("streaming FindAll")]
    public void Expired_unpublished_group_returns_capacity_even_when_worker_disposal_throws(string mode)
    {
        using var fixture = new DeadlineAdmissionFixture();
        fixture.Returned = () =>
        {
            fixture.Workers.Last().ThrowOnDispose = true;
            fixture.Clock.Advance(TimeSpan.FromSeconds(11));
        };
        using var searcher = fixture.Searcher(mode);
        var error = Record.Exception(() => DeadlineAdmissionFixture.Execute(searcher, mode));
        fixture.AssertReleased(); // assert reservation return independently of exception identity
        Assert.All(fixture.ReturnedBatches.Last(), session => Assert.Equal(typeof(LdapConnectionProvider.Session).FullName,
            Assert.Throws<ObjectDisposedException>(() => session.ExecuteTransport(_ => true)).ObjectName));
        Assert.DoesNotContain("open", fixture.Trace);
        Assert.IsType<TimeoutException>(error);
        fixture.Returned = null;
        DeadlineAdmissionFixture.Execute(searcher, mode);
        fixture.AssertReleased();
    }

    [Fact]
    public void Core_expiry_after_wrapping_sessions_preserves_timeout_and_returns_throwing_owner()
    {
        using var fixture = new DeadlineAdmissionFixture();
        fixture.Creating = (_, _, _) =>
        {
            var worker = fixture.Workers.Last(); worker.ThrowOnDispose = true;
            worker.SessionsRead = () => fixture.Clock.Advance(TimeSpan.FromSeconds(11));
        };
        var started = fixture.Clock.GetTimestamp();
        TimeSpan Remaining()
        {
            var left = DeadlineAdmissionFixture.ClientBudget - fixture.Clock.GetElapsedTime(started);
            return left > TimeSpan.Zero ? left : throw new TimeoutException("Controlled deadline after wrapping.");
        }
        var error = Record.Exception(() => fixture.Open(fixture.Root.BuildOptions(), 2,
            ReferralChasingOption.None, Remaining));
        fixture.AssertReleased();
        Assert.Equal("Controlled deadline after wrapping.", Assert.IsType<TimeoutException>(error).Message);
        Assert.DoesNotContain("open", fixture.Trace);
    }

    [Fact]
    public async Task Caller_cancellation_of_held_managed_admission_remains_cancellation()
    {
        using var fixture = new DeadlineAdmissionFixture();
        var held = fixture.Open(fixture.Root.BuildOptions(), 2, ReferralChasingOption.None);
        using var caller = new CancellationTokenSource();
        var pending = Task.Factory.StartNew(() => Record.Exception(() => fixture.Open(fixture.Root.BuildOptions(), 1,
            ReferralChasingOption.None, token: caller.Token)), CancellationToken.None,
            TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            Assert.True(SpinWait.SpinUntil(() => fixture.Pool.Snapshot.Waiting == 1, TimeSpan.FromSeconds(5)));
            caller.Cancel();
            Assert.IsType<OperationCanceledException>(await pending.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
            Assert.Equal(1, fixture.Pool.Snapshot.Total);
        }
        finally { caller.Cancel(); foreach (var session in held) session.Dispose(); await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
        fixture.AssertReleased();
    }
}
