using System.Runtime.ExceptionServices;

namespace AdForLinux.FunctionalTests;

// Dedicated test workers avoid blocking the ThreadPool that serves fixture TLS/LDAP.
// No identity APIs here. The caller checks flowed identity inside each operation.
internal sealed class WindowsDiagnosticConcurrent
{
    private int readyCount, starts;
    internal int Ready => Volatile.Read(ref readyCount);
    internal int Starts => Volatile.Read(ref starts);
    internal void Run(Action<int> operation)
    {
        using var ready = new CountdownEvent(2);
        using var start = new ManualResetEventSlim();
        var tasks = new List<Task>();
        int released = 0;
        Exception? failure = null;
        try
        {
            for (int index = 0; index < 2; index++)
            {
                int worker = index;
                tasks.Add(Task.Factory.StartNew(() =>
                {
                    Interlocked.Increment(ref readyCount);
                    ready.Signal();
                    start.Wait();
                    if (Volatile.Read(ref released) == 0) return;
                    Interlocked.Increment(ref starts);
                    operation(worker);
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            }
            if (!ready.Wait(TimeSpan.FromSeconds(3))) throw new TimeoutException("Diagnostic workers did not become ready.");
            Volatile.Write(ref released, 1);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            start.Set(); // Also releases partial startup without running operations.
            try { Task.WaitAll(tasks.ToArray()); }
            catch (Exception error) { failure ??= error; }
        }
        // Every started task has finished before callers restore impersonation or dispose leases.
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
