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
    {
        var request = new SearchRequest(
            null,                     // empty base DN = rootDSE
            "(objectClass=*)",
            ProtocolScope.Base,
            attributes);

        var response = (SearchResponse)connection.SendRequest(request);

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (response.Entries.Count == 0)
        {
            return result;
        }

        var entry = response.Entries[0];
        foreach (string name in entry.Attributes.AttributeNames)
        {
            var attribute = entry.Attributes[name];
            if (attribute.Count > 0)
            {
                result[name] = attribute[0]?.ToString() ?? string.Empty;
            }
        }

        return result;
    }

    /// <summary>The base DN of the domain, e.g. DC=samdom,DC=example,DC=com.</summary>
    public static string? GetDefaultNamingContext(LdapConnection connection)
    {
        var values = Read(connection, "defaultNamingContext");
        return values.TryGetValue("defaultNamingContext", out var dn) ? dn : null;
    }
}
