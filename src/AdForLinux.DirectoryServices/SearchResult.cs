using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// One entry returned by <see cref="DirectorySearcher"/>, like Microsoft's
/// <c>SearchResult</c>. Read the attributes through <see cref="Properties"/>.
/// </summary>
public sealed class SearchResult
{
    private readonly DirectoryEntry _searchRoot;

    internal SearchResult(SearchResultEntry entry, DirectoryEntry searchRoot)
    {
        _searchRoot = searchRoot;
        Path = searchRoot.PathForDn(entry.DistinguishedName);

        var properties = new ResultPropertyCollection();
        var grouped = new Dictionary<string, List<object>>(StringComparer.OrdinalIgnoreCase);
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
        properties.Set("adspath", new object[] { Path });
        Properties = properties;
    }

    /// <summary>The <c>LDAP://…</c> path of this result.</summary>
    public string Path { get; }

    /// <summary>The attributes that were loaded for this result.</summary>
    public ResultPropertyCollection Properties { get; }

    /// <summary>Opens this result as a full <see cref="DirectoryEntry"/>.</summary>
    public DirectoryEntry GetDirectoryEntry()
    {
        var dn = Path.Substring(Path.IndexOf('/', "LDAP://".Length) + 1);
        return _searchRoot.CreateEntryForDn(dn);
    }
}
