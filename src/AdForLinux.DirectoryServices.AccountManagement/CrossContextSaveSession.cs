using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

// One operation owns each session. Responses retain result codes and references
// until the preflight validates them; no general DirectorySearcher projection.
internal sealed class CrossContextSaveSession : IDisposable
{
    internal static readonly Func<LdapConnectionOptions, CrossContextSaveSession> DefaultFactory =
        static options => new CrossContextSaveSession(options);
    private readonly LdapConnectionProvider.Session? lease;
    private readonly LdapConnection? connection;
    private readonly ICrossContextExecutorTransport? controlled;
    internal bool CanWrite => controlled is not null;
    internal CrossContextSaveSession(ICrossContextExecutorTransport controlled) => this.controlled = controlled;
    internal CrossContextSaveSession(LdapConnectionOptions options)
    {
        lease = LdapConnectionProvider.Acquire(options);
        connection = lease.Connection;
    }
    internal CrossContextSaveSession(LdapConnectionProvider.Session lease)
    { this.lease = lease; connection = lease.Connection; }
    // Controlled transport boundary uses the same request/response path as production.
    internal CrossContextSaveSession(LdapConnection connection) => this.connection = connection;
    internal SearchResponse Search(SearchRequest request, TimeSpan remaining)
    {
        if (controlled is not null) return (SearchResponse)controlled.Send(request, remaining);
        if (lease is null)
        {
            connection!.Timeout = remaining;
            return (SearchResponse)connection.SendRequest(request);
        }
        try { return (SearchResponse)connection!.SendRequest(request, remaining); }
        catch (Exception error) { LdapConnectionProvider.ReportFailure(connection!, error); throw; }
    }
    internal DirectoryResponse SendWrite(DirectoryRequest request, TimeSpan remaining)
        => controlled?.Send(request, remaining)
            ?? throw new NotSupportedException("Live cross-context writes are not enabled.");
    public void Dispose()
    {
        if (controlled is not null) controlled.Dispose();
        else if (lease is not null) lease.Dispose();
        else connection!.Dispose();
    }
}
