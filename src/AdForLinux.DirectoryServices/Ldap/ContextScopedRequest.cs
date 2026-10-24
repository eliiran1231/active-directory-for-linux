namespace AdForLinux.DirectoryServices.Ldap;

// Concrete production adapters own a single preconstructed request. No connection
// or user operation delegate escapes this boundary. Generic only for pure tests.
internal interface IContextRequestLease<out TResult> : IDisposable
{
    void Prepare();
    TResult Send();
    void Invalidate();
}

internal static class ContextScopedRequest
{
    internal static TResult Execute<TResult>(
        Func<WindowsLdapContext?> capture,
        Func<WindowsLdapContext?, bool, IContextRequestLease<TResult>> acquire,
        CancellationToken cancellationToken = default, ContextRequestBoundary? boundary = null)
    {
        T At<T>(string stage, Func<T> action) => boundary is null ? action() : boundary.Invoke(stage, action);
        WindowsLdapContext? Read() { try { return capture(); } catch { return null; } }
        cancellationToken.ThrowIfCancellationRequested();
        var context = Read();
        IContextRequestLease<TResult>? lease = null;
        try
        {
            lease = acquire(context, context.HasValue);
            return At("acquired", () =>
            {
                var afterAcquire = Read();
                cancellationToken.ThrowIfCancellationRequested();
                lease.Prepare();
                return At("send", () =>
                {
                    var beforeSend = Read();
                    if (context.HasValue && (context != afterAcquire || context != beforeSend))
                    {
                        lease.Invalidate();
                        lease.Dispose();
                        lease = null;
                        context = null;
                        lease = acquire(null, false);
                        lease.Prepare();
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    try { return lease.Send(); }
                    catch { lease.Invalidate(); throw; }
                    finally
                    {
                        try
                        {
                            At("complete", () =>
                            {
                                if (!context.HasValue || context != Read()) lease.Invalidate();
                                return 0;
                            });
                        }
                        catch { lease.Invalidate(); } // Diagnostic failure is recorded separately; preserve send outcome.
                    }
                });
            });
        }
        catch { lease?.Invalidate(); throw; }
        finally
        {
            if (lease is not null)
            {
                try
                {
                    At("return", () =>
                    {
                        if (!context.HasValue || context != Read()) lease.Invalidate();
                        return 0;
                    });
                }
                catch { lease.Invalidate(); }
                finally { try { lease.Dispose(); } catch { } }
            }
        }
    }
}
