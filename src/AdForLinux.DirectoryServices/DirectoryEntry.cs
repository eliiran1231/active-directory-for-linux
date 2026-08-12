using System.ComponentModel;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

#pragma warning disable CA1416 // Security descriptors are transported as LDAP bytes; no local OS ACL is accessed.

namespace AdForLinux.DirectoryServices;

/// <summary>
/// One object in the directory, like Microsoft's <c>DirectoryEntry</c>, but
/// talking to the server through S.DS.Protocols so it runs on Linux.
///
/// This step covers reading: open by path, then read <see cref="Properties"/>,
/// <see cref="Name"/>, <see cref="SchemaClassName"/>, and <see cref="Guid"/>.
/// Writing arrives in a later step.
/// </summary>
public class DirectoryEntry : Component
{
    private string? _username;
    private string? _password;
    private AuthenticationTypes _authenticationType;
    private LdapConnectionOptions? _connectionOptionsOverride;

    private LdapPath _path;
    private LdapConnection? _connection;
    private PropertyCollection? _properties;
    private bool _isNew;
    private bool _usePropertyCache = true;
    private DirectoryEntryConfiguration? _options;
    private ActiveDirectorySecurity? _objectSecurity;
    private bool _objectSecurityChanged;

    /// <summary>Creates an unbound entry, like Microsoft's parameterless constructor.</summary>
    public DirectoryEntry()
    {
        _path = new LdapPath(null, null, string.Empty);
        _authenticationType = AuthenticationTypes.Secure;
    }

    /// <summary>
    /// Creates an entry from an ADSI native object. ADSI native objects do not
    /// exist on Linux, so use an LDAP path instead.
    /// </summary>
    public DirectoryEntry(object nativeAdsObject)
    {
        ArgumentNullException.ThrowIfNull(nativeAdsObject);
        throw new PlatformNotSupportedException(
            "DirectoryEntry(object) requires an ADSI native object, which is not available on Linux. Use an LDAP path.");
    }

    /// <summary>Opens an entry from an <c>LDAP://host/DN</c> path, anonymous bind.</summary>
    public DirectoryEntry(string path)
        : this(path, null, null, AuthenticationTypes.Secure)
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

    /// <summary>Opens an entry using an AccountManagement LDAP bind configuration.</summary>
    internal DirectoryEntry(string path, LdapConnectionOptions connectionOptions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(connectionOptions);
        _path = LdapPath.Parse(path);
        _username = connectionOptions.BindDn;
        _password = connectionOptions.BindPassword;
        _authenticationType = connectionOptions.UseSsl
            ? AuthenticationTypes.SecureSocketsLayer
            : AuthenticationTypes.None;
        _connectionOptionsOverride = connectionOptions;
    }

    /// <summary>The <c>LDAP://…</c> path this entry was opened with.</summary>
    public string Path
    {
        get => !_path.HasHost && string.IsNullOrEmpty(_path.DistinguishedName) ? string.Empty : _path.ToString();
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _connectionOptionsOverride = null;
            ResetBinding(string.IsNullOrWhiteSpace(value)
                ? new LdapPath(null, null, string.Empty)
                : LdapPath.Parse(value));
        }
    }

    /// <summary>Gets or sets the authentication options for this entry.</summary>
    public AuthenticationTypes AuthenticationType
    {
        get => _authenticationType;
        set
        {
            if (_authenticationType != value)
            {
                _authenticationType = value;
                _connectionOptionsOverride = null;
                ResetConnection();
            }
        }
    }

    /// <summary>Gets or sets the user name used to bind to LDAP.</summary>
    public string? Username
    {
        get => _username;
        set
        {
            if (!string.Equals(_username, value, StringComparison.Ordinal))
            {
                _username = value;
                _connectionOptionsOverride = null;
                ResetConnection();
            }
        }
    }

    /// <summary>Gets or sets the password used to bind to LDAP.</summary>
    public string? Password
    {
        private get => _password;
        set
        {
            if (!string.Equals(_password, value, StringComparison.Ordinal))
            {
                _password = value;
                _connectionOptionsOverride = null;
                ResetConnection();
            }
        }
    }

    /// <summary>Gets or sets whether property changes are cached until <see cref="CommitChanges"/>.</summary>
    public bool UsePropertyCache
    {
        get => _usePropertyCache;
        set
        {
            if (value == _usePropertyCache)
            {
                return;
            }

            // Microsoft flushes the current cache before switching to immediate
            // writes. This includes a pending ObjectSecurity assignment.
            if (!value)
            {
                CommitChanges();
            }

            _usePropertyCache = value;
        }
    }

    /// <summary>The distinguished name of this object.</summary>
    public string DistinguishedName => _path.DistinguishedName;

    /// <summary>
    /// The relative name of this object, e.g. <c>CN=Jeff Smith</c> — the first
    /// component of the DN, including its attribute type, like Microsoft.
    /// </summary>
    public string Name => LdapDistinguishedName.RelativeName(_path.DistinguishedName);

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

    /// <summary>The object GUID in the provider's string form.</summary>
    public string NativeGuid => Guid == Guid.Empty ? string.Empty : Guid.ToString("B");

    /// <summary>ADSI native objects are not available through LDAP protocols.</summary>
    public object NativeObject => throw new PlatformNotSupportedException(
        "DirectoryEntry.NativeObject requires ADSI/COM and is not available on Linux.");

    /// <summary>Gets the LDAP provider options associated with this entry.</summary>
    public DirectoryEntryConfiguration Options => _options ??= new DirectoryEntryConfiguration(this);

    /// <summary>Gets or sets this entry's Active Directory security descriptor.</summary>
    public ActiveDirectorySecurity ObjectSecurity
    {
        get
        {
            EnsureAccessControlSupported();
            return _objectSecurity ??= ReadObjectSecurity();
        }
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            EnsureAccessControlSupported();
            _objectSecurity = value;
            _objectSecurityChanged = true;
            CommitIfNotCaching();
        }
    }

    /// <summary>The parent entry, or <see langword="null"/> for a naming-context root.</summary>
    public DirectoryEntry? Parent
    {
        get
        {
            var parentDn = LdapDistinguishedName.Parent(_path.DistinguishedName);
            return parentDn is null ? null : CreateEntryForDn(parentDn);
        }
    }

    /// <summary>ADSI schema entries are not available through the portable LDAP API.</summary>
    public DirectoryEntry SchemaEntry => throw new PlatformNotSupportedException(
        "DirectoryEntry.SchemaEntry requires ADSI schema-provider behavior, which is not available on Linux.");

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
        var objectSecurityWritten = false;

        if (_isNew)
        {
            var add = new AddRequest(_path.DistinguishedName);
            foreach (var property in (IEnumerable<PropertyValueCollection>)Properties)
            {
                if (property.Count > 0)
                {
                    add.Attributes.Add(ToAttribute(property));
                }
            }

            objectSecurityWritten = AddObjectSecurity(add);

            connection.SendRequest(add);
            _isNew = false;
        }
        else
        {
            EnsureLoaded();
            var modify = new ModifyRequest(_path.DistinguishedName);
            foreach (var property in (IEnumerable<PropertyValueCollection>)_properties!)
            {
                if (!property.Changed)
                {
                    continue;
                }

                modify.Modifications.Add(ToModification(property));
            }

            objectSecurityWritten = AddObjectSecurity(modify);

            if (modify.Modifications.Count > 0)
            {
                connection.SendRequest(modify);
            }
        }

        foreach (var property in (IEnumerable<PropertyValueCollection>)_properties!)
        {
            property.ResetChanged();
        }

        if (objectSecurityWritten)
        {
            // DirectoryObjectSecurity does not expose a way to clear its
            // internal modification flags. Discard the successfully written
            // instance so the next access reloads a clean descriptor from AD.
            _objectSecurity = null;
        }

        _objectSecurityChanged = false;
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

    /// <summary>
    /// Changes an AD password with the atomic delete-old/add-new unicodePwd
    /// operation required for a user-initiated password change.
    /// </summary>
    internal void ChangePasswordImmediate(byte[] oldPassword, byte[] newPassword)
    {
        var deletion = new DirectoryAttributeModification
        {
            Name = "unicodePwd",
            Operation = DirectoryAttributeOperation.Delete,
        };
        deletion.Add(oldPassword);

        var addition = new DirectoryAttributeModification
        {
            Name = "unicodePwd",
            Operation = DirectoryAttributeOperation.Add,
        };
        addition.Add(newPassword);

        var request = new ModifyRequest(_path.DistinguishedName);
        request.Modifications.Add(deletion);
        request.Modifications.Add(addition);
        GetConnection().SendRequest(request);
    }

    internal byte[] ReadSecurityDescriptorImmediate(SecurityMasks masks)
    {
        var request = new SearchRequest(
            _path.DistinguishedName,
            "(objectClass=*)",
            ProtocolScope.Base,
            "nTSecurityDescriptor");
        request.Controls.Add(new SecurityDescriptorFlagControl(
            (System.DirectoryServices.Protocols.SecurityMasks)(int)masks));

        var response = (SearchResponse)GetConnection().SendRequest(request);
        if (response.Entries.Count == 0
            || response.Entries[0].Attributes["nTSecurityDescriptor"] is not { Count: > 0 } attribute
            || attribute[0] is not byte[] binaryForm)
        {
            throw new InvalidOperationException("The directory entry did not return a binary security descriptor.");
        }

        return binaryForm;
    }

    internal void ReplaceSecurityDescriptorImmediate(byte[] binaryForm, SecurityMasks masks)
    {
        var replacement = new DirectoryAttributeModification
        {
            Name = "nTSecurityDescriptor",
            Operation = DirectoryAttributeOperation.Replace,
        };
        replacement.Add(binaryForm);

        var request = new ModifyRequest(_path.DistinguishedName);
        request.Modifications.Add(replacement);
        request.Controls.Add(new SecurityDescriptorFlagControl(
            (System.DirectoryServices.Protocols.SecurityMasks)(int)masks));
        GetConnection().SendRequest(request);
    }

    /// <summary>
    /// Adds and removes individual values of one attribute in a single request,
    /// without rewriting the values that are already there. Used for group
    /// membership, where replacing the whole list would be unsafe.
    /// </summary>
    internal void ApplyValueChanges(
        string attributeName,
        IReadOnlyCollection<string> toAdd,
        IReadOnlyCollection<string> toRemove)
    {
        if (toAdd.Count == 0 && toRemove.Count == 0)
        {
            return;
        }

        var request = new ModifyRequest(_path.DistinguishedName);

        if (toRemove.Count > 0)
        {
            var deletion = new DirectoryAttributeModification
            {
                Name = attributeName,
                Operation = DirectoryAttributeOperation.Delete,
            };
            foreach (var value in toRemove)
            {
                deletion.Add(value);
            }

            request.Modifications.Add(deletion);
        }

        if (toAdd.Count > 0)
        {
            var addition = new DirectoryAttributeModification
            {
                Name = attributeName,
                Operation = DirectoryAttributeOperation.Add,
            };
            foreach (var value in toAdd)
            {
                addition.Add(value);
            }

            request.Modifications.Add(addition);
        }

        GetConnection().SendRequest(request);
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

    /// <summary>Deletes one direct child without requesting recursive tree deletion.</summary>
    internal void DeleteChild(string relativeName)
    {
        var distinguishedName = string.IsNullOrEmpty(_path.DistinguishedName)
            ? relativeName
            : $"{relativeName},{_path.DistinguishedName}";
        GetConnection().SendRequest(new DeleteRequest(distinguishedName));
    }

    /// <summary>Builds an unsaved child entry. CommitChanges creates it.</summary>
    internal static DirectoryEntry NewChild(DirectoryEntry parent, string relativeName, string schemaClassName)
    {
        var dn = $"{relativeName},{parent._path.DistinguishedName}";
        var path = new LdapPath(parent._path.Host, parent._path.Port, dn).ToString();

        var child = new DirectoryEntry(path, parent._username, parent._password, parent._authenticationType)
        {
            _isNew = true,
        };
        child._properties = new PropertyCollection(child.OnPropertyChanged);

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
        _objectSecurity = null;
        _objectSecurityChanged = false;
        EnsureLoaded();
    }

    /// <summary>Re-reads the specified attributes into the local property cache.</summary>
    public void RefreshCache(string[] propertyNames)
    {
        ArgumentNullException.ThrowIfNull(propertyNames);

        // LDAP treats an empty attribute list as "all user attributes", while
        // ADSI GetInfoEx with no names does not turn a partial refresh into a
        // full managed-cache replacement. Request LDAP's explicit no-attributes
        // selector so the call still validates/binds the entry without changing
        // any cached property.
        if (propertyNames.Length == 0)
        {
            _ = ReadProperties(new[] { "1.1" });
            return;
        }

        var refreshed = ReadProperties(propertyNames);
        var properties = _properties ?? new PropertyCollection(OnPropertyChanged);
        foreach (var propertyName in propertyNames)
        {
            if (propertyName is null)
            {
                continue;
            }

            properties.RemoveCached(propertyName);

            var unrangedName = WithoutRangeSpecifier(propertyName);
            if (!string.Equals(unrangedName, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                properties.RemoveCached(unrangedName);
            }
        }

        foreach (var property in (IEnumerable<PropertyValueCollection>)refreshed)
        {
            // Active Directory can answer a ranged request with a different
            // upper bound (including '*'). Cache it under the requested name
            // so the caller can retrieve the returned chunk.
            var cacheName = propertyNames.FirstOrDefault(requested =>
                requested is not null
                && HasRangeSpecifier(requested)
                && string.Equals(
                    WithoutRangeSpecifier(requested),
                    WithoutRangeSpecifier(property.PropertyName),
                    StringComparison.OrdinalIgnoreCase))
                ?? property.PropertyName;

            properties.ReplaceLoaded(cacheName, property);
        }

        _properties = properties;

        if (propertyNames.Contains("nTSecurityDescriptor", StringComparer.OrdinalIgnoreCase))
        {
            _objectSecurity = null;
            _objectSecurityChanged = false;
        }
    }

    /// <summary>Closes this entry and releases its LDAP connection.</summary>
    public void Close() => Dispose();

    /// <summary>Determines whether an LDAP path resolves to an entry.</summary>
    public static bool Exists(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            using var entry = new DirectoryEntry(path);
            entry.RefreshCache(new[] { "objectClass" });
            return true;
        }
        catch (DirectoryOperationException ex) when (ex.Response.ResultCode == ResultCode.NoSuchObject)
        {
            return false;
        }
    }

    /// <summary>Renames this entry under its existing parent.</summary>
    public void Rename(string newName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        MoveOrRename(LdapDistinguishedName.Parent(_path.DistinguishedName), newName);
    }

    /// <summary>Moves this entry beneath <paramref name="newParent"/>.</summary>
    public void MoveTo(DirectoryEntry newParent)
    {
        ArgumentNullException.ThrowIfNull(newParent);
        MoveOrRename(newParent.DistinguishedName, LdapDistinguishedName.RelativeName(_path.DistinguishedName));
    }

    /// <summary>Moves this entry beneath <paramref name="newParent"/> and renames it.</summary>
    public void MoveTo(DirectoryEntry newParent, string newName)
    {
        ArgumentNullException.ThrowIfNull(newParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        MoveOrRename(newParent.DistinguishedName, newName);
    }

    /// <summary>
    /// ADSI exposes a provider copy operation; LDAP has no interoperable copy
    /// operation, so callers must create a child and copy supported attributes explicitly.
    /// </summary>
    public DirectoryEntry CopyTo(DirectoryEntry newParent) =>
        throw new PlatformNotSupportedException("LDAP does not define an interoperable DirectoryEntry copy operation.");

    /// <inheritdoc cref="CopyTo(DirectoryEntry)"/>
    public DirectoryEntry CopyTo(DirectoryEntry newParent, string newName) =>
        throw new PlatformNotSupportedException("LDAP does not define an interoperable DirectoryEntry copy operation.");

    /// <summary>ADSI provider invocation is not available through LDAP protocols.</summary>
    public object? Invoke(string methodName, params object?[]? args) =>
        throw new PlatformNotSupportedException("DirectoryEntry.Invoke requires ADSI/COM and is not available on Linux.");

    /// <summary>ADSI provider invocation is not available through LDAP protocols.</summary>
    public object? InvokeGet(string propertyName) =>
        throw new PlatformNotSupportedException("DirectoryEntry.InvokeGet requires ADSI/COM and is not available on Linux.");

    /// <summary>ADSI provider invocation is not available through LDAP protocols.</summary>
    public void InvokeSet(string propertyName, params object?[]? args) =>
        throw new PlatformNotSupportedException("DirectoryEntry.InvokeSet requires ADSI/COM and is not available on Linux.");

    private void EnsureLoaded(string[]? propertyNames = null)
    {
        if (_properties is not null)
        {
            return;
        }

        var loadDefaultProperties = propertyNames is not { Length: > 0 };
        var requestedProperties = loadDefaultProperties
            ? new[] { "*", "nTSecurityDescriptor" }
            : propertyNames!;
        _properties = ReadProperties(requestedProperties, loadDefaultProperties);
    }

    private PropertyCollection ReadProperties(
        string[] requestedProperties,
        bool loadDefaultProperties = false)
    {
        var connection = GetConnection();
        var request = new SearchRequest(
            _path.DistinguishedName,
            "(objectClass=*)",
            ProtocolScope.Base,
            requestedProperties);

        if (loadDefaultProperties || requestedProperties.Contains(
                "nTSecurityDescriptor", StringComparer.OrdinalIgnoreCase))
        {
            request.Controls.Add(new SecurityDescriptorFlagControl(
                (System.DirectoryServices.Protocols.SecurityMasks)(int)EffectiveSecurityMasks()));
        }

        var response = (SearchResponse)connection.SendRequest(request);
        var properties = new PropertyCollection(OnPropertyChanged);

        if (response.Entries.Count > 0)
        {
            LoadEntry(response.Entries[0], properties);
        }

        return properties;
    }

    private static bool HasRangeSpecifier(string propertyName) =>
        !string.Equals(WithoutRangeSpecifier(propertyName), propertyName, StringComparison.Ordinal);

    private static string WithoutRangeSpecifier(string propertyName) => string.Join(
        ";",
        propertyName.Split(';').Where(part =>
            !part.StartsWith("range=", StringComparison.OrdinalIgnoreCase)));

    private ActiveDirectorySecurity ReadObjectSecurity()
    {
        var masks = EffectiveSecurityMasks();
        return new ActiveDirectorySecurity(ReadSecurityDescriptorImmediate(masks), masks);
    }

    private static void EnsureAccessControlSupported()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "ActiveDirectorySecurity derives from the Windows-only System.Security.AccessControl object-security model.");
        }
    }

    private bool AddObjectSecurity(DirectoryRequest request)
    {
        if (_objectSecurity is null || (!_objectSecurityChanged && !_objectSecurity.IsModified()))
        {
            return false;
        }

        var binaryForm = _objectSecurity.GetSecurityDescriptorBinaryForm();
        switch (request)
        {
            case AddRequest add:
                add.Attributes.Add(new DirectoryAttribute("nTSecurityDescriptor", binaryForm));
                break;
            case ModifyRequest modify:
                var replacement = new DirectoryAttributeModification
                {
                    Name = "nTSecurityDescriptor",
                    Operation = DirectoryAttributeOperation.Replace,
                };
                replacement.Add(binaryForm);
                modify.Modifications.Add(replacement);
                break;
        }

        request.Controls.Add(new SecurityDescriptorFlagControl(
            (System.DirectoryServices.Protocols.SecurityMasks)(int)_objectSecurity.RetrievedMasks));
        return true;
    }

    private void CommitIfNotCaching()
    {
        if (!UsePropertyCache)
        {
            CommitChanges();
        }
    }

    private SecurityMasks EffectiveSecurityMasks() => Options.SecurityMasks == SecurityMasks.None
        ? SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl
        : Options.SecurityMasks;

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
        return _connectionOptionsOverride is null
            ? new DirectoryEntry(path, _username, _password, _authenticationType)
            : new DirectoryEntry(path, _connectionOptionsOverride);
    }

    /// <summary>Builds the LDAP path for a DN on this entry's server.</summary>
    internal string PathForDn(string distinguishedName) =>
        new LdapPath(_path.Host, _path.Port, distinguishedName).ToString();

    internal LdapConnectionOptions BuildOptions()
    {
        if (_connectionOptionsOverride is not null)
        {
            return _connectionOptionsOverride;
        }

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

    private void OnPropertyChanged(PropertyValueCollection property)
    {
        if (_usePropertyCache || _isNew)
        {
            return;
        }

        var request = new ModifyRequest(_path.DistinguishedName);
        request.Modifications.Add(ToModification(property));
        GetConnection().SendRequest(request);
        property.ResetChanged();
    }

    private void MoveOrRename(string? parentDn, string newName)
    {
        if (string.IsNullOrEmpty(parentDn))
        {
            throw new InvalidOperationException("The entry has no parent naming context to move or rename within.");
        }

        var request = new ModifyDNRequest(_path.DistinguishedName, parentDn, newName)
        {
            DeleteOldRdn = true,
        };
        GetConnection().SendRequest(request);
        ResetBinding(new LdapPath(_path.Host, _path.Port, $"{newName},{parentDn}"));
    }

    private void ResetBinding(LdapPath path)
    {
        _path = path;
        _properties = null;
        _objectSecurity = null;
        _objectSecurityChanged = false;
        ResetConnection();
    }

    private void ResetConnection()
    {
        _connection?.Dispose();
        _connection = null;
    }

    /// <summary>Releases the LDAP connection held by this entry.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ResetConnection();
        }

        base.Dispose(disposing);
    }
}
