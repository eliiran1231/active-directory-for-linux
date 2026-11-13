using System.Reflection;
using AdForLinux.DirectoryServices.Ldap;

// A refused live operation is a test-boundary failure, never an oracle result.
internal static class MirrorExceptionCapture
{
    private sealed class BoundaryViolation(Exception inner)
        : Exception("A mirror attempted an operation blocked by the offline guard.",inner) { }

    internal static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception error)
        {
            if (IsBoundary(error)) throw new BoundaryViolation(error);
            return error;
        }
    }

    private static bool IsBoundary(Exception error) =>
        error is BoundaryViolation ||
        (error is InvalidOperationException && error.Message==OfflineTestGuard.Message) ||
        (error is AggregateException aggregate && aggregate.InnerExceptions.Any(IsBoundary)) ||
        (error.InnerException is { } inner && IsBoundary(inner));

    // Infrastructure regression checks, excluded from Microsoft observation totals.
    internal static void ValidateBoundary()
    {
        var local=new InvalidOperationException("local API validation control");
        if (!ReferenceEquals(local,Capture(() => throw local)) || Capture(() => { }) is not null)
            throw new Exception("Ordinary API exception capture changed");
        foreach (var wrap in new Func<Exception,Exception>[] {
                     error => error,
                     error => new TargetInvocationException(error),
                     error => new Exception("outer control",error),
                     error => new AggregateException(new InvalidOperationException("other control"),error) })
        {
            ExpectBoundary(() =>
            {
                try { OfflineTestGuard.RequireLiveAccess(); }
                catch (Exception error) { throw wrap(error); }
            });
        }
        ExpectBoundary(() => Capture(() => OfflineTestGuard.RequireLiveAccess()));
    }

    private static void ExpectBoundary(Action action)
    {
        try { Capture(action); }
        catch (BoundaryViolation) { return; }
        throw new Exception("Offline guard refusal was accepted as an API observation");
    }
}
