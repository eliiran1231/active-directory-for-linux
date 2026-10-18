namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>Exclusive ownership, including creation and disposal, under hard capacity limits.</summary>
internal sealed class BoundedConnectionPool<TKey, T> : IDisposable where TKey : notnull where T : class, IDisposable
{
    internal sealed class Bucket
    {
        internal int Count;
        internal readonly List<(T Value, long Returned)> Idle = [];
    }

    private readonly object gate = new();
    private readonly Dictionary<TKey, Bucket> buckets = [];
    private readonly int perKeyLimit, totalLimit, waiterLimit;
    private readonly TimeSpan idleTimeout, acquisitionTimeout;
    private readonly TimeProvider clock;
    private readonly ITimer? timer;
    private int total, waiting;
    private bool disposed;
    private long created, reused, destroyed, failures, waits, timeouts;

    internal BoundedConnectionPool(int perKeyLimit = 8, int totalLimit = 64,
        TimeSpan? idleTimeout = null, TimeSpan? acquisitionTimeout = null,
        TimeProvider? clock = null, bool startTimer = true, int waiterLimit = 256)
    {
        if (perKeyLimit < 1 || totalLimit < 1 || waiterLimit < 1) throw new ArgumentOutOfRangeException(nameof(perKeyLimit));
        this.perKeyLimit = perKeyLimit;
        this.totalLimit = totalLimit;
        this.waiterLimit = waiterLimit;
        this.idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(60);
        this.acquisitionTimeout = acquisitionTimeout ?? TimeSpan.FromSeconds(30);
        if (this.idleTimeout <= TimeSpan.Zero || this.acquisitionTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(idleTimeout));
        this.clock = clock ?? TimeProvider.System;
        if (startTimer) timer = this.clock.CreateTimer(_ => Sweep(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    // Aggregate counters intentionally contain no keys, endpoints or identities.
    internal (int Total, int Keys, int Waiting, long Created, long Reused, long Destroyed, long Failures, long Waits, long Timeouts) Snapshot
    {
        get { lock (gate) return (total, buckets.Count, waiting, created, reused, destroyed, failures, waits, timeouts); }
    }

    internal Lease Acquire(TKey key, Func<T> create, CancellationToken cancellationToken = default, bool reusable = true)
    {
        ArgumentNullException.ThrowIfNull(create);
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        using var registration = cancellationToken.Register(() => { lock (gate) Monitor.PulseAll(gate); });
        while (true)
        {
            Bucket? reserved = null;
            (TKey Key, Bucket Bucket, T Value)? retire = null;
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                cancellationToken.ThrowIfCancellationRequested();
                if (elapsed.Elapsed >= acquisitionTimeout) { timeouts++; throw new TimeoutException("LDAP connection acquisition timed out."); }
                buckets.TryGetValue(key, out var bucket);
                if (reusable && bucket is not null && bucket.Idle.Count > 0)
                {
                    var item = bucket.Idle[^1];
                    bucket.Idle.RemoveAt(bucket.Idle.Count - 1);
                    if (clock.GetElapsedTime(item.Returned) < idleTimeout)
                    {
                        reused++;
                        return new Lease(this, key, bucket, item.Value, true);
                    }
                    retire = (key, bucket, item.Value);
                }
                else if ((bucket?.Count ?? 0) < perKeyLimit && total < totalLimit)
                {
                    if (bucket is null) buckets.Add(key, bucket = new Bucket());
                    bucket.Count++; total++; reserved = bucket;
                }
                else if (total >= totalLimit)
                {
                    // An incompatible idle key must not monopolize global capacity.
                    foreach (var pair in buckets)
                    {
                        if (pair.Value.Idle.Count == 0) continue;
                        var item = pair.Value.Idle[0];
                        pair.Value.Idle.RemoveAt(0);
                        retire = (pair.Key, pair.Value, item.Value);
                        break;
                    }
                }
                if (reserved is null && retire is null)
                {
                    if (waiting >= waiterLimit) throw new TimeoutException("LDAP connection acquisition queue is full.");
                    var remaining = acquisitionTimeout - elapsed.Elapsed;
                    if (remaining <= TimeSpan.Zero) { timeouts++; throw new TimeoutException("LDAP connection acquisition timed out."); }
                    waiting++; waits++;
                    try { Monitor.Wait(gate, remaining > TimeSpan.FromMilliseconds(int.MaxValue) ? int.MaxValue : Math.Max(1, (int)remaining.TotalMilliseconds)); }
                    finally { waiting--; }
                }
            }
            if (retire is { } victim) Destroy(victim.Key, victim.Bucket, victim.Value);
            if (reserved is null) continue;
            T value;
            try { value = create(); }
            catch
            {
                lock (gate) { failures++; ReleaseReservation(key, reserved); }
                throw;
            }
            bool reject;
            lock (gate)
            {
                created++;
                reject = disposed || cancellationToken.IsCancellationRequested;
                if (!reject) return new Lease(this, key, reserved, value, reusable);
            }
            Destroy(key, reserved, value);
            cancellationToken.ThrowIfCancellationRequested();
            throw new ObjectDisposedException(nameof(BoundedConnectionPool<TKey, T>));
        }
    }

    internal void Sweep()
    {
        List<(TKey Key, Bucket Bucket, T Value)> expired = [];
        lock (gate)
        {
            foreach (var pair in buckets)
            {
                for (var i = pair.Value.Idle.Count - 1; i >= 0; i--)
                {
                    var item = pair.Value.Idle[i];
                    if (!disposed && clock.GetElapsedTime(item.Returned) < idleTimeout) continue;
                    pair.Value.Idle.RemoveAt(i);
                    expired.Add((pair.Key, pair.Value, item.Value));
                }
            }
        }
        foreach (var item in expired) Destroy(item.Key, item.Bucket, item.Value);
    }

    private void Return(TKey key, Bucket bucket, T value, bool reusable)
    {
        lock (gate)
        {
            if (!disposed && reusable)
            {
                bucket.Idle.Add((value, clock.GetTimestamp()));
                Monitor.PulseAll(gate);
                return;
            }
        }
        Destroy(key, bucket, value);
    }

    private void Destroy(TKey key, Bucket bucket, T value)
    {
        try { value.Dispose(); }
        // Disposal errors cannot strand reservations or terminate timer callbacks.
        catch { lock (gate) failures++; }
        finally { lock (gate) { destroyed++; ReleaseReservation(key, bucket); } }
    }

    private void ReleaseReservation(TKey key, Bucket bucket)
    {
        bucket.Count--; total--;
        if (bucket.Count == 0) buckets.Remove(key);
        Monitor.PulseAll(gate);
    }

    public void Dispose()
    {
        lock (gate) { if (disposed) return; disposed = true; Monitor.PulseAll(gate); }
        timer?.Dispose();
        Sweep();
    }

    internal sealed class Lease : IDisposable
    {
        private BoundedConnectionPool<TKey, T>? owner;
        private readonly TKey key;
        private readonly Bucket bucket;
        private readonly T value;
        private int reusable;
        internal Lease(BoundedConnectionPool<TKey, T> owner, TKey key, Bucket bucket, T value, bool reusable)
        { this.owner = owner; this.key = key; this.bucket = bucket; this.value = value; this.reusable = reusable ? 1 : 0; }
        internal T Value => Volatile.Read(ref owner) is not null ? value : throw new ObjectDisposedException(nameof(Lease));
        internal void Invalidate() => Interlocked.Exchange(ref reusable, 0);
        public void Dispose() => Interlocked.Exchange(ref owner, null)?.Return(key, bucket, value, Volatile.Read(ref reusable) != 0);
    }
}
