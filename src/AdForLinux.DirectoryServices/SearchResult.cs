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

    internal SearchResult(SearchResultEntry entry, SearchResultOrigin origin, DirectoryEntry schemaRoot, LdapConnection? schemaConnection = null)
    {
        _authority = origin.Authority;
        _searchRoot = origin.Copy(entry.DistinguishedName);
        var path = _searchRoot.Path;

        using var schemaLease = schemaConnection is null ? schemaRoot.AcquireConnection(_authority.Validate, schema: true) : null;
        _authority.Validate();
        Properties = Materialize(path, entry.Attributes.AttributeNames.Cast<string>(),
            SearchEntryReader.Read(entry, schemaConnection ?? schemaLease!.Connection));
        _authority.Validate();
    }

    // Materialize completely while the caller owns its distinct schema lease.
    // Returned results retain authority/recipe data, never the borrowed transport.
    internal SearchResult(LdapTransportEntry entry, SearchResultOrigin origin, ILdapRequestTransport schemaTransport,
        Func<TimeSpan>? remaining = null, CancellationToken cancellationToken = default)
    {
        _authority = origin.Authority;
        _searchRoot = origin.Copy(entry.DistinguishedName);
        _authority.Validate();
        Properties = Materialize(_searchRoot.Path, entry.Attributes.Keys, SearchEntryReader.Read(entry, schemaTransport, remaining, cancellationToken));
        cancellationToken.ThrowIfCancellationRequested();
        if (remaining is not null && remaining() <= TimeSpan.Zero) throw new TimeoutException("Result materialization deadline expired.");
        _authority.Validate();
    }

    private static ResultPropertyCollection Materialize(string path, IEnumerable<string> returnedNames,
        IEnumerable<(string Name, object Value)> values)
    {
        var properties = new ResultPropertyCollection();
        var grouped = new Dictionary<string, List<object>>(StringComparer.OrdinalIgnoreCase);
        // Preserve returned names even when a types-only response has no values.
        foreach (var name in returnedNames) grouped[name] = [];
        foreach (var (name, value) in values)
        {
            if (!grouped.TryGetValue(name, out var list)) grouped[name] = list = [];
            list.Add(value);
        }
        foreach (var (name, items) in grouped) properties.Set(name, items);
        properties.Set("adspath", new object[] { path });
        return properties;
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
