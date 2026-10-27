using System.Diagnostics;

namespace AdForLinux.DirectoryServices.Ldap;

// A worker is the only capacity unit here: never hold a worker while waiting
// for a second connection pool. Eight groups admit at most sixteen sessions;
// retiring/unverified processes continue consuming their worker slots.
internal static class LdapRestrictedOperation
{
    private static readonly NativeLdapWorkerPool Workers = new(8);
    internal static (int Tracked, int Retiring, int Unverified) Snapshot => Workers.Snapshot;
    internal static int LastExitOutcome => Workers.LastExitOutcome;

    static LdapRestrictedOperation()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Workers.Dispose();
        System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(typeof(LdapRestrictedOperation).Assembly)!.Unloading += _ => Workers.Dispose();
    }

    internal static LdapConnectionProvider.Session[] Acquire(LdapConnectionOptions options, int count,
        ReferralChasingOption referrals, CancellationToken cancellationToken, TimeSpan? timeout = null)
    {
        var started = Stopwatch.GetTimestamp();
        var snapshot = options.Clone();
        var selected = snapshot.RestrictedKerberos ?? throw new ArgumentException("An explicit restricted profile is required.");
        selected.ValidateRecipe(snapshot);
        if (count is < 1 or > 2 || referrals != ReferralChasingOption.None)
            throw new PlatformNotSupportedException("Restricted operations require one or two sessions without referrals.");
        var budget = timeout is { } requested && requested < snapshot.Timeout ? requested : snapshot.Timeout;
        TimeSpan Remaining()
        {
            cancellationToken.ThrowIfCancellationRequested();
            var left = budget - Stopwatch.GetElapsedTime(started);
            if (left <= TimeSpan.Zero) throw new TimeoutException("Restricted worker admission deadline expired.");
            return left;
        }
        _ = selected.WorkerProfile(count, Remaining());
        OfflineTestGuard.RequireLiveAccess();
        // This filesystem inspection is cooperative, not a promise to interrupt
        // an unresponsive filesystem. Its elapsed time still consumes the budget.
        using var deployment = LdapWorkerDeployment.Validate(selected.DeploymentDirectory);
        deployment.RequireRestrictedComposition();
        // Native bind profiles use whole seconds. Round up only that internal
        // limit; the parent's exact remaining budget still bounds startup and
        // publication, including slow or blocked native calls in the worker.
        var nativeTimeout = TimeSpan.FromSeconds(Math.Ceiling(Remaining().TotalSeconds));
        var worker = Workers.AcquireAsync(deployment, selected.WorkerProfile(count, nativeTimeout), Remaining(), cancellationToken)
            .GetAwaiter().GetResult();
        try
        {
            _ = Remaining();
            var sessions = Wrap(worker.Client.Sessions, worker, snapshot);
            try { _ = Remaining(); return sessions; }
            catch { foreach (var session in sessions) session.Dispose(); throw; }
        }
        catch { worker.Dispose(); throw; }
    }

    // The same ownership constructor is exercised by deterministic tests. The
    // caller transfers owner only after argument validation; no binding is faked.
    internal static LdapConnectionProvider.Session[] Wrap(IReadOnlyList<ILdapRequestTransport> transports,
        IDisposable owner, LdapConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (transports.Count is < 1 or > 2 || transports.Any(value => value is null))
            throw new ArgumentException("A group requires one or two transports.", nameof(transports));
        var group = new Group(owner);
        var sessions = new List<LdapConnectionProvider.Session>();
        try
        {
            foreach (var transport in transports)
            {
                var member = group.AddMember();
                BoundLdapSession? resource = null;
                try
                {
                    resource = new BoundLdapSession(transport, member, options,
                        new LdapAuthenticationSource(options), ReferralChasingOption.None);
                    sessions.Add(new LdapConnectionProvider.Session(resource, group.Retire, group.Validate));
                }
                catch { if (resource is null) member.Dispose(); else resource.Dispose(); throw; }
            }
            return sessions.ToArray();
        }
        catch { group.Retire(); foreach (var session in sessions) session.Dispose(); throw; }
        finally { group.Release(); } // construction ownership; members now own the group
    }

    private sealed class Group(IDisposable owner)
    {
        private IDisposable? worker = owner;
        private int references = 1;
        internal void Validate() => ObjectDisposedException.ThrowIf(Volatile.Read(ref worker) is null, this);
        internal IDisposable AddMember() { Interlocked.Increment(ref references); return new Member(this); }
        internal void Retire() => Interlocked.Exchange(ref worker, null)?.Dispose();
        internal void Release() { if (Interlocked.Decrement(ref references) == 0) Retire(); }
        private sealed class Member(Group group) : IDisposable
        {
            private Group? retained = group;
            public void Dispose() => Interlocked.Exchange(ref retained, null)?.Release();
        }
    }
}
