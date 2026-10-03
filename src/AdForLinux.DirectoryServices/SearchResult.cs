using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// One entry returned by <see cref="DirectorySearcher"/>, like Microsoft's
/// <c>SearchResult</c>. Read the attributes through <see cref="Properties"/>.
/// </summary>
public class SearchResult
{
    private readonly DirectoryEntry _searchRoot;

    internal SearchResult(SearchResultEntry entry, DirectoryEntry searchRoot)
    {
        // Capture credentials and transport configuration before callers can
        // mutate or dispose the search root. This entry never opens a connection.
        _searchRoot = searchRoot.CreateEntryForDn(entry.DistinguishedName);
        var path = searchRoot.PathForDn(entry.DistinguishedName);

        var properties = new ResultPropertyCollection();
        var grouped = new Dictionary<string, List<object>>(StringComparer.OrdinalIgnoreCase);
        // Types-only LDAP responses include attribute names without values.
        // Start from the names actually returned, not the requested names.
        foreach (string name in entry.Attributes.AttributeNames)
        {
            grouped[name] = new List<object>();
        }

        foreach (var (name, value) in SearchEntryReader.Read(entry, searchRoot.GetSchemaConnection()))
        {
            if (!grouped.TryGetValue(name, out var list))
            {
                list = new List<object>();
                grouped[name] = list;
            }

            list.Add(value);
        }

        foreach (var (name, values) in grouped)
        {
            properties.Set(name, values);
        }

        // Microsoft also exposes the path as the "adspath" property.
        properties.Set("adspath", new object[] { path });
        Properties = properties;
    }

    /// <summary>The <c>LDAP://…</c> path of this result.</summary>
    public string Path => (string)Properties["ADsPath"][0]!;

    /// <summary>The attributes that were loaded for this result.</summary>
    public ResultPropertyCollection Properties { get; }

    /// <summary>Opens this result as a full <see cref="DirectoryEntry"/>.</summary>
    public DirectoryEntry GetDirectoryEntry()
    {
        return _searchRoot.CreateEntryForPath(Path);
    }

    internal SearchResult(DirectoryEntry searchRoot, ResultPropertyCollection properties)
    {
        _searchRoot = searchRoot;
        Properties = properties;
    }

    internal SearchResult Snapshot()
    {
        var properties = new ResultPropertyCollection();
        foreach (string name in Properties.PropertyNames)
        {
            properties.Set(name, Properties[name].Cast<object>().ToArray());
        }
        return new SearchResult(_searchRoot, properties);
    }
}
