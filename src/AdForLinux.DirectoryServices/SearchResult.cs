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
    private readonly DirectoryEntry.BindingAuthority _authority;

    internal SearchResult(SearchResultEntry entry, DirectoryEntry searchRoot)
        : this(entry, new SearchResultOrigin(searchRoot, searchRoot.CaptureBindingAuthority()), searchRoot) { }

    internal SearchResult(SearchResultEntry entry, SearchResultOrigin origin, DirectoryEntry schemaRoot)
    {
        _authority = origin.Authority;
        _searchRoot = origin.Copy(entry.DistinguishedName);
        var path = _searchRoot.Path;

        var properties = new ResultPropertyCollection();
        var grouped = new Dictionary<string, List<object>>(StringComparer.OrdinalIgnoreCase);
        // Types-only LDAP responses include attribute names without values.
        // Start from the names actually returned, not the requested names.
        foreach (string name in entry.Attributes.AttributeNames)
        {
            grouped[name] = new List<object>();
        }

        foreach (var (name, value) in SearchEntryReader.Read(entry, schemaRoot.GetAuthorityConnection(_authority, schema: true)))
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
        _authority.Validate();
        Properties = properties;
    }

    /// <summary>The <c>LDAP://…</c> path of this result.</summary>
    public string Path => (string)Properties["ADsPath"][0]!;

    /// <summary>The attributes that were loaded for this result.</summary>
    public ResultPropertyCollection Properties { get; }

    /// <summary>Opens this result as a full <see cref="DirectoryEntry"/>.</summary>
    public DirectoryEntry GetDirectoryEntry()
    {
        return _authority.Checked(() => _searchRoot.CreateEntryForPath(Path));
    }

    internal SearchResult(DirectoryEntry searchRoot, ResultPropertyCollection properties)
    {
        _authority = searchRoot.CaptureBindingAuthority();
        _searchRoot = searchRoot.CopyBinding(_authority);
        Properties = properties;
    }

    private SearchResult(DirectoryEntry capturedRoot, DirectoryEntry.BindingAuthority authority, ResultPropertyCollection properties)
    { _searchRoot = capturedRoot; _authority = authority; Properties = properties; }

    internal SearchResult Snapshot()
    {
        var properties = new ResultPropertyCollection();
        foreach (string name in Properties.PropertyNames)
        {
            properties.Set(name, Properties[name].Cast<object>()
                .Select(value => value is byte[] bytes ? bytes.ToArray() : value).ToArray());
        }
        return new SearchResult(_searchRoot, _authority, properties);
    }
}

// Captured before dispatch. Result construction never consults a mutable root
// for endpoint credentials. Its schema connection is admitted by the same token.
internal sealed class SearchResultOrigin
{
    private readonly DirectoryEntry template;
    internal DirectoryEntry.BindingAuthority Authority { get; }
    internal string DistinguishedName => template.DistinguishedName;
    internal SearchResultOrigin(DirectoryEntry root, DirectoryEntry.BindingAuthority authority)
    { Authority = authority; template = root.CopyBinding(authority); }
    internal DirectoryEntry Copy(string? dn = null)
        => Authority.Checked(() => template.CreateEntryForDn(dn ?? DistinguishedName));
}
