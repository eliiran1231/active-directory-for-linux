using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// One object in the directory, like Microsoft's <c>DirectoryEntry</c>, but
/// talking to the server through S.DS.Protocols so it runs on Linux.
///
/// This step covers reading: open by path, then read <see cref="Properties"/>,
/// <see cref="Name"/>, <see cref="SchemaClassName"/>, and <see cref="Guid"/>.
/// Writing arrives in a later step.
/// </summary>
public class DirectoryEntry : IDisposable
{
    private readonly string? _username;
    private readonly string? _password;
    private readonly AuthenticationTypes _authenticationType;

    private LdapPath _path;
    private LdapConnection? _connection;
    private PropertyCollection? _properties;
    private bool _isNew;

    /// <summary>Opens an entry from an <c>LDAP://host/DN</c> path, anonymous bind.</summary>
    public DirectoryEntry(string path)
        : this(path, null, null, AuthenticationTypes.None)
    {
    }

    /// <summary>Opens an entry with a user and password (simple bind).</summary>
    public DirectoryEntry(string path, string? username, string? password)
        : this(path, username, password, AuthenticationTypes.None)
    {
    }

    /// <summary>Opens an entry with a user, password, and bind options.</summary>
    public DirectoryEntry(string path, string? username, string? password, AuthenticationTypes authenticationType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = LdapPath.Parse(path);
        _username = username;
        _password = password;
        _authenticationType = authenticationType;
    }

    /// <summary>The <c>LDAP://…</c> path this entry was opened with.</summary>
    public string Path
    {
        get => _path.ToString();
        set => _path = LdapPath.Parse(value);
    }

    /// <summary>The distinguished name of this object.</summary>
    public string DistinguishedName => _path.DistinguishedName;

    /// <summary>
    /// The relative name of this object, e.g. <c>CN=Jeff Smith</c> — the first
    /// component of the DN, including its attribute type, like Microsoft.
    /// </summary>
    public string Name => RelativeName(_path.DistinguishedName);

    /// <summary>
    /// The most specific structural class, e.g. <c>user</c> or <c>group</c> —
    /// the last value of <c>objectClass</c>, as AD orders it.
    /// </summary>
    public string? SchemaClassName
    {
        get
        {
            var classes = Properties["objectClass"];
            return classes.Count > 0 ? classes[classes.Count - 1]?.ToString() : null;
        }
    }

    /// <summary>The object's <c>objectGUID</c>.</summary>
    public Guid Guid
    {
        get
        {
            var value = Properties["objectGUID"].Value;
            return value is byte[] bytes && bytes.Length == 16 ? new Guid(bytes) : Guid.Empty;
        }
    }

    /// <summary>The loaded attributes. Reading this binds and fetches on first use.</summary>
    public PropertyCollection Properties
    {
        get
        {
            EnsureLoaded();
            return _properties!;
        }
    }

    /// <summary>The child objects directly under this one. Use to add or remove.</summary>
    public DirectoryEntries Children => new(this);

    /// <summary>
    /// Writes pending changes to the server. For a new object (from
    /// <c>Children.Add</c>) this creates it; for an existing one it sends only
    /// the changed attributes, like Microsoft's <c>CommitChanges</c>.
    /// </summary>
    public void CommitChanges()
    {
        var connection = GetConnection();

        if (_isNew)
        {
            var add = new AddRequest(_path.DistinguishedName);
            foreach (var property in Properties)
            {
                if (property.Count > 0)
                {
                    add.Attributes.Add(ToAttribute(property));
                }
            }

            connection.SendRequest(add);
            _isNew = false;
        }
        else
        {
            EnsureLoaded();
            var modify = new ModifyRequest(_path.DistinguishedName);
            foreach (var property in _properties!)
            {
                if (!property.Changed)
                {
                    continue;
                }

                modify.Modifications.Add(ToModification(property));
            }

            if (modify.Modifications.Count > 0)
            {
                connection.SendRequest(modify);
            }
        }

        foreach (var property in _properties!)
        {
            property.ResetChanged();
        }
    }

    /// <summary>
    /// Sends a single Replace for one attribute right away, without touching the
    /// other pending changes. Used for operations that act immediately, like a
    /// password reset.
    /// </summary>
    internal void ReplaceAttributeImmediate(string attributeName, object value)
    {
        var connection = GetConnection();
        var modification = new DirectoryAttributeModification
        {
            Name = attributeName,
            Operation = DirectoryAttributeOperation.Replace,
        };
        AddValue(modification, value);

        var request = new ModifyRequest(_path.DistinguishedName);
        request.Modifications.Add(modification);
        connection.SendRequest(request);
    }

    /// <summary>Deletes this object and everything under it.</summary>
    public void DeleteTree()
    {
        var connection = GetConnection();
        var delete = new DeleteRequest(_path.DistinguishedName);
        // Ask the server to delete the whole subtree (OID 1.2.840.113556.1.4.805).
        delete.Controls.Add(new TreeDeleteControl());
        connection.SendRequest(delete);
    }

    /// <summary>Builds an unsaved child entry. CommitChanges creates it.</summary>
    internal static DirectoryEntry NewChild(DirectoryEntry parent, string relativeName, string schemaClassName)
    {
        var dn = $"{relativeName},{parent._path.DistinguishedName}";
        var path = new LdapPath(parent._path.Host, parent._path.Port, dn).ToString();

        var child = new DirectoryEntry(path, parent._username, parent._password, parent._authenticationType)
        {
            _isNew = true,
            _properties = new PropertyCollection(),
        };

        // The structural class; AD fills in the rest of the class chain.
        child._properties["objectClass"].Value = schemaClassName;
        return child;
    }

    private static DirectoryAttribute ToAttribute(PropertyValueCollection property)
    {
        var attribute = new DirectoryAttribute { Name = property.PropertyName };
        foreach (var value in property)
        {
            AddValue(attribute, value);
        }

        return attribute;
    }

    private static DirectoryAttributeModification ToModification(PropertyValueCollection property)
    {
        var modification = new DirectoryAttributeModification
        {
            Name = property.PropertyName,
            Operation = property.Count == 0
                ? DirectoryAttributeOperation.Delete   // cleared = remove the attribute
                : DirectoryAttributeOperation.Replace,
        };

        foreach (var value in property)
        {
            AddValue(modification, value);
        }

        return modification;
    }

    private static void AddValue(DirectoryAttribute attribute, object value)
    {
        switch (value)
        {
            case byte[] bytes:
                attribute.Add(bytes);
                break;
            case string text:
                attribute.Add(text);
                break;
            default:
                attribute.Add(value.ToString());
                break;
        }
    }

    /// <summary>Re-reads this object's attributes from the server.</summary>
    public void RefreshCache()
    {
        _properties = null;
        EnsureLoaded();
    }

    private void EnsureLoaded()
    {
        if (_properties is not null)
        {
            return;
        }

        var connection = GetConnection();
        var request = new SearchRequest(
            _path.DistinguishedName,
            "(objectClass=*)",
            ProtocolScope.Base,
            "*");

        var response = (SearchResponse)connection.SendRequest(request);
        var properties = new PropertyCollection();

        if (response.Entries.Count > 0)
        {
            LoadEntry(response.Entries[0], properties);
        }

        _properties = properties;
    }

    private static void LoadEntry(SearchResultEntry entry, PropertyCollection properties)
    {
        foreach (var (name, value) in SearchEntryReader.Read(entry))
        {
            properties.GetOrAdd(name).AddLoaded(value);
        }
    }

    internal LdapConnection GetConnection() => _connection ??= LdapConnectionFactory.CreateBound(BuildOptions());

    internal string? ServerHost => _path.Host;

    internal int? ServerPort => _path.Port;

    /// <summary>
    /// Builds a new entry for another DN on the same server, carrying the same
    /// credentials and bind options. Used for search results, parents, children.
    /// </summary>
    internal DirectoryEntry CreateEntryForDn(string distinguishedName)
    {
        var path = new LdapPath(_path.Host, _path.Port, distinguishedName).ToString();
        return new DirectoryEntry(path, _username, _password, _authenticationType);
    }

    /// <summary>Builds the LDAP path for a DN on this entry's server.</summary>
    internal string PathForDn(string distinguishedName) =>
        new LdapPath(_path.Host, _path.Port, distinguishedName).ToString();

    internal LdapConnectionOptions BuildOptions()
    {
        if (!_path.HasHost)
        {
            throw new NotSupportedException(
                "Serverless binding is not supported on Linux. Include the server in the " +
                "path, e.g. LDAP://dc1.example.com/DC=example,DC=com.");
        }

        var useSsl = _authenticationType.HasFlag(AuthenticationTypes.SecureSocketsLayer)
                     || _path.Port == 636;
        var port = _path.Port ?? (useSsl ? 636 : 389);

        return new LdapConnectionOptions
        {
            Host = _path.Host!,
            Port = port,
            UseSsl = useSsl,
            BindDn = _username,
            BindPassword = _password,
        };
    }

    /// <summary>First RDN component of a DN, e.g. "CN=Jeff" from "CN=Jeff,DC=x".</summary>
    private static string RelativeName(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
        {
            return string.Empty;
        }

        // Split on the first comma that is not escaped with a backslash.
        for (var i = 0; i < distinguishedName.Length; i++)
        {
            if (distinguishedName[i] == ',' && (i == 0 || distinguishedName[i - 1] != '\\'))
            {
                return distinguishedName.Substring(0, i);
            }
        }

        return distinguishedName;
    }

    public void Dispose()
    {
        _connection?.Dispose();
        _connection = null;
        GC.SuppressFinalize(this);
    }
}
