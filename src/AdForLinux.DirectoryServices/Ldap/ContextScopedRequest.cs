namespace AdForLinux.DirectoryServices.Ldap;

// Production adapters own one preconstructed request; no connection or user
// operation delegate escapes this boundary. Generic only for isolated tests.
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
        CancellationToken cancellationToken = default)
    {
        WindowsLdapContext? Read() { try { return capture(); } catch { return null; } }
        cancellationToken.ThrowIfCancellationRequested();
        var context = Read();
        IContextRequestLease<TResult>? lease = null;
        try
        {
            lease = acquire(context, context.HasValue);
            var afterAcquire = Read();
            cancellationToken.ThrowIfCancellationRequested();
            lease.Prepare();
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
                try { if (!context.HasValue || context != Read()) lease.Invalidate(); }
                catch { lease.Invalidate(); }
            }
        }
        catch { lease?.Invalidate(); throw; }
        finally
        {
            if (lease is not null)
            {
                try { if (!context.HasValue || context != Read()) lease.Invalidate(); }
                catch { lease.Invalidate(); }
                finally { try { lease.Dispose(); } catch { } }
            }
        }
    }
}
