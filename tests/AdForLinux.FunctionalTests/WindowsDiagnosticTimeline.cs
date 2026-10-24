using System.Diagnostics;

namespace AdForLinux.FunctionalTests;

// Only fixed labels and synthetic numeric IDs; never record wire text, identities or keys.
internal sealed class WindowsDiagnosticTimeline
{
    internal const int Limit = 64;
    private readonly object gate = new();
    private readonly long origin = Stopwatch.GetTimestamp();
    private readonly List<string> events = [];
    private int dropped;
    internal int Dropped { get { lock (gate) return dropped; } }
    internal void Add(string role, int connection, int message, int operation, string stage)
    {
        if (role is not ("client" or "source" or "target") ||
            stage is not ("accept" or "tls" or "bind" or "search" or "referral-send" or "response-send" or
                "arrive" or "release" or "timeout" or "close" or "fault" or "native-enter" or "native-exit" or "native-error") ||
            connection < 0 || message < 0 || operation is < 0 or > 2)
            throw new ArgumentException("Invalid fixed diagnostic event.");
        lock (gate)
        {
            if (events.Count == Limit) { dropped++; return; }
            long elapsed = (long)(Stopwatch.GetElapsedTime(origin).TotalMilliseconds * 1000);
            events.Add(FormattableString.Invariant($"{events.Count + 1}:{elapsed}:{role}:{connection}:{message}:{operation}:{stage}"));
        }
    }
    internal string Snapshot() { lock (gate) return string.Join(';', events); }
    internal bool ExactOperations()
    {
        lock (gate)
        {
            if (dropped != 0) return false;
            var rows = events.Select(e => e.Split(':')).ToArray();
            foreach (int operation in new[] { 1, 2 })
                foreach (var pair in new[] { ("client", "native-enter"), ("client", "native-exit"),
                    ("source", "search"), ("target", "search"), ("target", "arrive"), ("target", "release"), ("target", "response-send") })
                    if (rows.Count(e => e[2] == pair.Item1 && e[5] == operation.ToString() && e[6] == pair.Item2) != 1) return false;
            return !rows.Any(e => e[6] is "timeout" or "native-error" or "fault");
        }
    }
    internal static string BaseDn(int operation) => operation switch
    { 1 => "CN=operation-1", 2 => "CN=operation-2", _ => throw new ArgumentOutOfRangeException(nameof(operation)) };
    internal static int Operation(byte[] dn) => dn.AsSpan().SequenceEqual("CN=operation-1"u8) ? 1 :
        dn.AsSpan().SequenceEqual("CN=operation-2"u8) ? 2 : throw new InvalidDataException("Unknown synthetic operation.");
}

// The timeout is deliberately fail-closed: the endpoint preserves the exception and
// closes that connection. This can provoke a native retry; timeline records precede it.
internal sealed class WindowsDiagnosticOverlap(WindowsDiagnosticTimeline timeline, TimeSpan timeout)
{
    private readonly TaskCompletionSource both = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int arrivals, timeouts;
    internal int Arrivals => Volatile.Read(ref arrivals);
    internal int Timeouts => Volatile.Read(ref timeouts);
    internal async Task Arrive(int connection, int message, int operation)
    {
        timeline.Add("target", connection, message, operation, "arrive");
        if (Interlocked.Increment(ref arrivals) == 2) both.TrySetResult();
        try { await both.Task.WaitAsync(timeout); }
        catch (TimeoutException)
        {
            Interlocked.Increment(ref timeouts);
            timeline.Add("target", connection, message, operation, "timeout");
            throw;
        }
        timeline.Add("target", connection, message, operation, "release");
    }
}
