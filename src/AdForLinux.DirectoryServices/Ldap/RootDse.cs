using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Reads the server's rootDSE — the anonymous entry at the empty base DN that
/// tells us the naming contexts, supported controls, and so on.
/// </summary>
internal static class RootDse
{
    /// <summary>
    /// Reads the requested rootDSE attributes. Returns each attribute's first
    /// value as a string. Missing attributes are simply absent from the map.
    /// </summary>
    public static Dictionary<string, string> Read(LdapConnection connection, params string[] attributes)
        => Read(new ProtocolsLdapTransport(connection), attributes);

    internal static Dictionary<string, string> Read(ILdapRequestTransport transport, params string[] attributes)
        => Read(transport, transport.Timeout, CancellationToken.None, attributes);

    internal static Dictionary<string, string> Read(ILdapRequestTransport transport, TimeSpan timeout,
        CancellationToken cancellationToken, params string[] attributes)
    {
        var response = LdapRequestDispatcher.Search(transport,
            new LdapSearchCommand("", "(objectClass=*)", ProtocolScope.Base, attributes, timeout), cancellationToken);
        if (response.Code != ResultCode.Success)
            throw LdapExceptionTranslator.Translate(response.Code, response.Diagnostic ?? "RootDSE search failed.");
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (response.Entries.Length == 0) return result;
        foreach (var (name, values) in response.Entries[0].Attributes)
            if (values.Length != 0) result[name] = System.Text.Encoding.UTF8.GetString(values[0]);
        return result;
    }

    /// <summary>The base DN of the domain, e.g. DC=samdom,DC=example,DC=com.</summary>
    public static string? GetDefaultNamingContext(LdapConnection connection)
        => GetDefaultNamingContext(new ProtocolsLdapTransport(connection));

    internal static string? GetDefaultNamingContext(ILdapRequestTransport transport)
    {
        var values = Read(transport, "defaultNamingContext");
        return values.TryGetValue("defaultNamingContext", out var dn) ? dn : null;
    }

    /// <summary>
    /// Gets the server backing an already-bound connection. Active Directory's
    /// rootDSE reports the concrete DC even when the client connected through a
    /// DNS alias. Other LDAP servers can fall back to the host name maintained
    /// by the native LDAP session.
    /// </summary>
    public static string GetConnectedServerName(LdapConnection connection)
        => GetConnectedServerName(new ProtocolsLdapTransport(connection));

    internal static string GetConnectedServerName(ILdapRequestTransport transport)
    {
        var values = Read(transport, "dnsHostName");
        if (values.TryGetValue("dnsHostName", out var dnsHostName) &&
            !string.IsNullOrWhiteSpace(dnsHostName))
        {
            return dnsHostName;
        }

        var sessionHostName = transport.ConnectedHost;
        return !string.IsNullOrWhiteSpace(sessionHostName)
            ? sessionHostName
            : throw new InvalidOperationException(
                "The LDAP protocol stack did not report the server backing the current connection.");
    }
}
