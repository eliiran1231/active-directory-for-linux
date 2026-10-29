namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class LdapRestrictedOperation
{
    // Same admission/idle/eviction algorithm as Basic. A resource is an entire
    // exclusive worker group, never an independently pooled query/schema member.
    // Workers still charges dying/unreaped processes after logical pool eviction.
    private static readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, ManagedWorker> Groups = new(8, 8, generationSource: LdapConnectionProvider.NewGeneration);
    internal static (long Created, long Reused) GroupCounters => (Groups.Snapshot.Created, Groups.Snapshot.Reused);

    private static LdapConnectionProvider.Session[] AcquireWorkerGroup(LdapConnectionOptions options, int count,
        ReferralChasingOption referrals, VerifiedDeployment deployment, Func<TimeSpan> remaining,
        CancellationToken cancellationToken, bool preferFresh, long minimumGeneration)
        => AcquireWorkerGroupCore(options, count, referrals, remaining, cancellationToken, Groups,
            (start, timeout, token) => Workers.AcquireAsync(deployment, start, timeout, token,
                () => Groups.EvictOneIdle()).GetAwaiter().GetResult(),
            preferFresh, minimumGeneration);

    internal static LdapConnectionProvider.Session[] AcquireWorkerGroupCore(LdapConnectionOptions options, int count,
        ReferralChasingOption referrals, Func<TimeSpan> remaining, CancellationToken cancellationToken,
        BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, ManagedWorker> pool,
        Func<LdapWorkerStart, TimeSpan, CancellationToken, IManagedWorker> create,
        bool preferFresh = false, long minimumGeneration = 0)
    {
        var profile = options.RestrictedKerberos!;
        profile.ValidateRecipe(options);
        if (count is < 1 or > 2 || referrals != ReferralChasingOption.None)
            throw new PlatformNotSupportedException("Managed workers require one or two sessions without referrals.");
        var context = profile.OwnedCredentials;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(remaining());
        while (true)
        {
            _ = remaining();
            using var generation = context?.Capture();
            var key = LdapConnectionProvider.ConnectionKey.CreateManagedKerberos(options, referrals, context?.Id ?? Guid.Empty, generation?.Version ?? 0, count);
            using var registration = context?.Register(generation!, key, pool, () => pool.Retire(key));
            if (context is not null && registration is null) continue;
            var lease = pool.Acquire(key, () =>
            {
                var started = generation?.Timestamp ?? 0;
                var start = profile.WorkerProfile(count, TimeSpan.FromSeconds(Math.Ceiling(remaining().TotalSeconds)))
                    with { OwnedCache = generation?.Bytes, RetainOwnedCache = generation is null ? null : generation.RetainStartup };
                var workerRegistration = registration?.Retain();
                IManagedWorker? worker = null;
                var retainedGeneration = false;
                try
                {
                    worker = create(start, remaining(), deadline.Token);
                    if (generation is not null)
                    {
                        generation.SetValidity(started, worker.CredentialLifetimeSeconds);
                        generation.RequireValid(); generation.Retain(); retainedGeneration = true;
                    }
                    return new ManagedWorker(worker, generation, workerRegistration);
                }
                catch
                {
                    try { worker?.Dispose(); }
                    finally
                    {
                        workerRegistration?.Dispose();
                        if (retainedGeneration) generation!.Dispose();
                    }
                    throw;
                }
            }, deadline.Token, reusable: context is not null, preferFresh: preferFresh, minimumGeneration: minimumGeneration);
            var transferred = false;
            try
            {
                _ = remaining();
                if (!lease.Value.Healthy || (context is not null && !context.Admit(generation!)))
                {
                    lease.Invalidate();
                    continue; // No application request has been exposed or sent.
                }
                var owner = new ManagedOperationOwner(lease, context, generation);
                var sessions = Wrap(lease.Value.Worker.Sessions, owner, options);
                try { _ = remaining(); transferred = true; return sessions; }
                catch
                {
                    transferred = true;
                    foreach (var session in sessions) { session.Invalidate(); session.Dispose(); }
                    throw;
                }
            }
            catch { lease.Invalidate(); throw; }
            finally { if (!transferred) lease.Dispose(); }
        }
    }

    private interface IManagedOperationOwner { void Invalidate(); }

    internal interface IManagedWorker : IDisposable
    {
        IReadOnlyList<ILdapRequestTransport> Sessions { get; }
        uint CredentialLifetimeSeconds { get; }
        bool Healthy { get; }
    }

    internal sealed class ManagedWorker(IManagedWorker worker,
        KerberosCredentialContext.Generation? generation,
        KerberosCredentialContext.Generation.Registration? registration = null) : IDisposable
    {
        private int disposed;
        internal IManagedWorker Worker => worker;
        internal bool Healthy => Volatile.Read(ref disposed) == 0 && worker.Healthy && generation?.Revoked != true;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try { worker.Dispose(); }
            finally { registration?.Dispose(); generation?.Dispose(); }
        }
    }

    private sealed class ManagedOperationOwner(
        BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, ManagedWorker>.Lease lease,
        KerberosCredentialContext? context, KerberosCredentialContext.Generation? generation) : IDisposable, IManagedOperationOwner
    {
        private int disposed;
        public void Invalidate() { lease.Invalidate(); lease.Value.Dispose(); }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try
            {
                if (!lease.Value.Healthy || (context is not null && !context.Admit(generation!))) lease.Invalidate();
            }
            catch { lease.Invalidate(); }
            finally { lease.Dispose(); }
        }
    }
}
