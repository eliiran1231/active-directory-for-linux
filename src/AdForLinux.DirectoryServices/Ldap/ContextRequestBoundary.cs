using System.Runtime.ExceptionServices;

namespace AdForLinux.DirectoryServices.Ldap;

// Invocation-local instrumentation, supplied only by the guarded diagnostic.
// Hooks see a stage and one-shot continuation, never a connection or result.
internal sealed class ContextRequestBoundary(Action<string, Action> scope)
{
    internal bool Failed { get; private set; }
    internal T Invoke<T>(string stage, Func<T> operation)
    {
        int called = 0;
        bool localFailure = false;
        bool active = true;
        int thread = Environment.CurrentManagedThreadId;
        T result = default!;
        ExceptionDispatchInfo? operationFailure = null;
        Exception? hookFailure = null;
        try
        {
            scope(stage, () =>
            {
                if (!Volatile.Read(ref active) || Environment.CurrentManagedThreadId != thread)
                { Failed = localFailure = true; throw new InvalidOperationException("Diagnostic continuation escaped its synchronous scope."); }
                if (Interlocked.Increment(ref called) != 1)
                { Failed = localFailure = true; throw new InvalidOperationException("Diagnostic continuation repeated."); }
                try { result = operation(); }
                catch (Exception error) { operationFailure = ExceptionDispatchInfo.Capture(error); throw; }
            });
        }
        catch (Exception error)
        {
            if (operationFailure?.SourceException != error) { Failed = localFailure = true; hookFailure = error; }
        }
        finally { Volatile.Write(ref active, false); }
        if (called != 1) Failed = localFailure = true;
        operationFailure?.Throw();
        if (hookFailure is not null || called != 1 || localFailure)
            throw new InvalidOperationException("Diagnostic boundary failed.");
        return result;
    }
}
