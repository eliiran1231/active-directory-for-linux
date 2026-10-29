namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>Exclusive ownership, including creation and disposal, under hard capacity limits.</summary>
internal sealed class BoundedConnectionPool<TKey, T> : IDisposable where TKey : notnull where T : class, IDisposable
{
    internal sealed class Bucket
    {
        internal int Count;
        internal readonly List<(T Value, long Returned, long Created)> Idle = [];
    }

    private readonly object gate = new();
    private readonly Dictionary<TKey, Bucket> buckets = [];
    private readonly int perKeyLimit, totalLimit, waiterLimit;
    private readonly TimeSpan idleTimeout, acquisitionTimeout;
    private readonly TimeProvider clock;
    private readonly ITimer? timer;
    private int total, waiting;
    private bool disposed;
    private long generation;
    internal long NewGeneration() { lock (gate) return ++generation; }
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

    internal Lease Acquire(TKey key, Func<T> create, CancellationToken cancellationToken = default,
        bool reusable = true, bool preferFresh = false, long minimumGeneration = 0)
        => AcquireBatch(key, 1, create, cancellationToken, reusable, preferFresh, minimumGeneration)[0];

    // Reserve an entire operation before creating any handles. A streaming request
    // and its concurrent schema reader must never each hold one slot while waiting
    // for the other's slot. A configuration too small for the operation fails early.
    internal Lease[] AcquireBatch(TKey key, int count, Func<T> create,
        CancellationToken cancellationToken = default, bool reusable = true, bool preferFresh = false, long minimumGeneration = 0)
    {
        if (count < 1) throw new ArgumentOutOfRangeException(nameof(count));
        return AcquireMany(Enumerable.Range(0, count).Select(_ =>
            new Request(key, create, reusable, preferFresh, minimumGeneration)).ToArray(), cancellationToken);
    }

    internal sealed record Request(TKey Key, Func<T> Create, bool Reusable = true,
        bool PreferFresh = false, long MinimumGeneration = 0);

    // Multiple endpoints use the same atomic admission as a streaming pair. No
    // operation holds a partial reservation while waiting for another endpoint.
    internal Lease[] AcquireMany(IReadOnlyList<Request> requests, CancellationToken cancellationToken = default)
    {
        if (requests.Count == 0) throw new ArgumentException("An operation must request at least one connection.", nameof(requests));
        foreach (var request in requests) ArgumentNullException.ThrowIfNull(request.Create);
        var groups = requests.GroupBy(request => request.Key).ToDictionary(group => group.Key, group => group.ToArray());
        if (requests.Count > totalLimit || groups.Values.Any(group => group.Length > perKeyLimit))
            throw new InvalidOperationException("The configured LDAP connection capacity cannot accommodate this operation.");
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        using var registration = cancellationToken.Register(() => { lock (gate) Monitor.PulseAll(gate); });
        while (true)
        {
            List<(Request Request, Bucket Bucket, T? Value, long Born)>? reserved = null;
            (TKey Key, Bucket Bucket, T Value)? retire = null;
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                cancellationToken.ThrowIfCancellationRequested();
                if (elapsed.Elapsed >= acquisitionTimeout) { timeouts++; throw new TimeoutException("LDAP connection acquisition timed out."); }
                foreach (var group in groups)
                {
                    if (!buckets.TryGetValue(group.Key, out var bucket)) continue;
                    var fresh = group.Value.Any(request => !request.Reusable || request.PreferFresh);
                    var minimum = group.Value.Max(request => request.MinimumGeneration);
                    var index = bucket.Idle.FindIndex(item => fresh || item.Created < minimum || clock.GetElapsedTime(item.Returned) >= idleTimeout);
                    if (index < 0) continue;
                    var item = bucket.Idle[index]; bucket.Idle.RemoveAt(index);
                    retire = (group.Key, bucket, item.Value); break;
                }
                if (retire is null)
                {
                    var missing = groups.ToDictionary(group => group.Key, group =>
                        Math.Max(0, group.Value.Length - (buckets.GetValueOrDefault(group.Key)?.Idle.Count ?? 0)));
                    var keyCapacity = missing.All(pair => (buckets.GetValueOrDefault(pair.Key)?.Count ?? 0) + pair.Value <= perKeyLimit);
                    if (keyCapacity && total + missing.Values.Sum() <= totalLimit)
                    {
                        reserved = [];
                        foreach (var request in requests)
                        {
                            if (!buckets.TryGetValue(request.Key, out var bucket)) buckets.Add(request.Key, bucket = new Bucket());
                            if (bucket.Idle.Count > 0)
                            {
                                var item = bucket.Idle[^1]; bucket.Idle.RemoveAt(bucket.Idle.Count - 1);
                                reserved.Add((request, bucket, item.Value, item.Created)); reused++;
                            }
                            else
                            {
                                bucket.Count++; total++;
                                reserved.Add((request, bucket, null, 0));
                            }
                        }
                    }
                    else if (keyCapacity)
                    {
                        // Evict only capacity that can help this acquisition, retaining
                        // the idle handles already needed by its requested endpoints.
                        foreach (var pair in buckets)
                        {
                            var needed = groups.TryGetValue(pair.Key, out var group) ? group.Length : 0;
                            if (pair.Value.Idle.Count <= needed) continue;
                            var item = pair.Value.Idle[0]; pair.Value.Idle.RemoveAt(0);
                            retire = (pair.Key, pair.Value, item.Value); break;
                        }
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
            try
            {
                for (var i = 0; i < reserved.Count; i++)
                {
                    var item = reserved[i];
                    if (item.Value is not null) continue;
                    cancellationToken.ThrowIfCancellationRequested();
                    long born;
                    lock (gate) born = ++generation;
                    var value = item.Request.Create();
                    reserved[i] = (item.Request, item.Bucket, value, born);
                    lock (gate) created++;
                }
                lock (gate)
                {
                    ObjectDisposedException.ThrowIf(disposed, this);
                    cancellationToken.ThrowIfCancellationRequested();
                    return reserved.Select(item => new Lease(this, item.Request.Key, item.Bucket,
                        item.Value!, item.Born, item.Request.Reusable)).ToArray();
                }
            }
            catch
            {
                lock (gate)
                {
                    failures++;
                    foreach (var item in reserved.Where(item => item.Value is null)) ReleaseReservation(item.Request.Key, item.Bucket);
                }
                foreach (var item in reserved.Where(item => item.Value is not null)) Destroy(item.Request.Key, item.Bucket, item.Value!);
                throw;
            }
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

    private void Return(TKey key, Bucket bucket, T value, long born, bool reusable)
    {
        lock (gate)
        {
            if (!disposed && reusable)
            {
                bucket.Idle.Add((value, clock.GetTimestamp(), born));
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
        private readonly long born;
        private int reusable;
        internal Lease(BoundedConnectionPool<TKey, T> owner, TKey key, Bucket bucket, T value, long born, bool reusable)
        { this.owner = owner; this.key = key; this.bucket = bucket; this.value = value; this.born = born; this.reusable = reusable ? 1 : 0; }
        internal T Value => Volatile.Read(ref owner) is not null ? value : throw new ObjectDisposedException(nameof(Lease));
        internal void Invalidate() => Interlocked.Exchange(ref reusable, 0);
        public void Dispose() => Interlocked.Exchange(ref owner, null)?.Return(key, bucket, value, born, Volatile.Read(ref reusable) != 0);
    }
}
