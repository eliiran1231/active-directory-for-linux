using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

// One operation owns each session. Responses retain result codes and references
// until the preflight validates them; no general DirectorySearcher projection.
internal sealed class CrossContextSaveSession : IDisposable
{
    private readonly LdapConnection connection;
    internal CrossContextSaveSession(LdapConnectionOptions options)
    {
        connection = LdapConnectionFactory.Create(options);
        try
        {
            LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.None);
            connection.Bind();
        }
        catch { connection.Dispose(); throw; }
    }
    // Controlled transport boundary uses the same request/response path as production.
    internal CrossContextSaveSession(LdapConnection connection) => this.connection = connection;
    internal SearchResponse Search(SearchRequest request, TimeSpan remaining)
    {
        connection.Timeout = remaining;
        return (SearchResponse)connection.SendRequest(request);
    }
    public void Dispose() => connection.Dispose();
}
