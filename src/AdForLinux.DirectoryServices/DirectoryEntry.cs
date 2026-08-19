using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
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
    private LdapConnection? _schemaConnection;
    private PropertyCollection? _properties;
    private bool _isNew;
    private bool _usePropertyCache = true;
    private DirectoryEntryConfiguration? _options;
    private ActiveDirectorySecurity? _objectSecurity;
    private bool _objectSecurityChanged;
    private bool _disposed;

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

    /// <summary>Opens an entry with a user and password using secure authentication.</summary>
    public DirectoryEntry(string path, string? username, string? password)
        : this(path, username, password, AuthenticationTypes.Secure)
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
        _authenticationType = connectionOptions.AuthenticationType switch
        {
            AuthType.Negotiate => AuthenticationTypes.Secure,
            AuthType.Anonymous => AuthenticationTypes.Anonymous,
            _ => AuthenticationTypes.None,
        };
        if (connectionOptions.UseSsl)
        {
            _authenticationType |= AuthenticationTypes.SecureSocketsLayer;
        }
        if (connectionOptions.Signing)
        {
            _authenticationType |= AuthenticationTypes.Signing;
        }
        if (connectionOptions.Sealing)
        {
            _authenticationType |= AuthenticationTypes.Sealing;
        }
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

    /// <summary>Retained for source compatibility; ADSI native objects are not available on Linux.</summary>
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
            ThrowIfDisposed();
            var parentDn = LdapDistinguishedName.Parent(_path.DistinguishedName);
            return parentDn is null ? null : CreateEntryForDn(parentDn);
        }
    }

    /// <summary>Gets the Active Directory schema class that describes this entry.</summary>
    public DirectoryEntry SchemaEntry
    {
        get
        {
            var schemaClassName = SchemaClassName;
            if (string.IsNullOrEmpty(schemaClassName))
            {
                throw new InvalidOperationException(
                    "The directory entry did not expose an objectClass to resolve in the schema.");
            }

            var connection = GetSchemaConnection();
            var rootDse = RootDse.Read(connection, "schemaNamingContext");
            if (!rootDse.TryGetValue("schemaNamingContext", out var schemaNamingContext)
                || string.IsNullOrEmpty(schemaNamingContext))
            {
                throw new InvalidOperationException(
                    "The directory server did not expose a schemaNamingContext in rootDSE.");
            }

            var request = new SearchRequest(
                schemaNamingContext,
                $"(&(objectClass=classSchema)(lDAPDisplayName={EscapeFilterValue(schemaClassName)}))",
                ProtocolScope.OneLevel,
                "lDAPDisplayName");
            var response = (SearchResponse)connection.SendRequestCompatible(request);
            if (response.Entries.Count != 1)
            {
                throw new InvalidOperationException(
                    $"The schema class '{schemaClassName}' could not be resolved under '{schemaNamingContext}'.");
            }

            var schemaEntry = CreateEntryForDn(response.Entries[0].DistinguishedName);
            schemaEntry._usePropertyCache = _usePropertyCache;
            return schemaEntry;
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

            connection.SendRequestCompatible(add);
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

                AddModifications(modify, property);
            }

            objectSecurityWritten = AddObjectSecurity(modify);

            if (modify.Modifications.Count > 0)
            {
                connection.SendRequestCompatible(modify);
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
        connection.SendRequestCompatible(request);
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
        GetConnection().SendRequestCompatible(request);
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

        var response = (SearchResponse)GetConnection().SendRequestCompatible(request);
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
        GetConnection().SendRequestCompatible(request);
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

        GetConnection().SendRequestCompatible(request);
    }

    /// <summary>Deletes this object and everything under it.</summary>
    public void DeleteTree()
    {
        var connection = GetConnection();
        var delete = new DeleteRequest(_path.DistinguishedName);
        // Ask the server to delete the whole subtree (OID 1.2.840.113556.1.4.805).
        delete.Controls.Add(new TreeDeleteControl());
        connection.SendRequestCompatible(delete);
    }

    /// <summary>Deletes one direct child without requesting recursive tree deletion.</summary>
    internal void DeleteChild(string relativeName)
    {
        var distinguishedName = string.IsNullOrEmpty(_path.DistinguishedName)
            ? relativeName
            : $"{relativeName},{_path.DistinguishedName}";
        GetConnection().SendRequestCompatible(new DeleteRequest(distinguishedName));
    }

    /// <summary>Builds an unsaved child entry. CommitChanges creates it.</summary>
    internal static DirectoryEntry NewChild(DirectoryEntry parent, string relativeName, string schemaClassName)
    {
        parent.ThrowIfDisposed();
        var dn = $"{relativeName},{parent._path.DistinguishedName}";
        var path = new LdapPath(parent._path.Host, parent._path.Port, dn).ToString();

        var child = parent._connectionOptionsOverride is null
            ? new DirectoryEntry(path, parent._username, parent._password, parent._authenticationType)
            : new DirectoryEntry(path, parent._connectionOptionsOverride.Clone());
        child._isNew = true;
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

    private static void AddModifications(ModifyRequest request, PropertyValueCollection property)
    {
        foreach (var change in property.Changes)
        {
            var modification = new DirectoryAttributeModification
            {
                Name = property.PropertyName,
                Operation = change.Type switch
                {
                    PropertyValueChangeType.Add => DirectoryAttributeOperation.Add,
                    PropertyValueChangeType.Delete => DirectoryAttributeOperation.Delete,
                    PropertyValueChangeType.Replace => DirectoryAttributeOperation.Replace,
                    PropertyValueChangeType.Clear => DirectoryAttributeOperation.Delete,
                    _ => throw new InvalidOperationException("Unknown property change type."),
                },
            };

            foreach (var value in change.Values)
            {
                AddValue(modification, value);
            }

            request.Modifications.Add(modification);
        }
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
            case bool boolean:
                attribute.Add(boolean ? "TRUE" : "FALSE");
                break;
            case DateTime dateTime:
                attribute.Add(FormatDirectoryTime(dateTime));
                break;
            case DateTimeOffset dateTimeOffset:
                attribute.Add(dateTimeOffset.UtcDateTime.ToString(
                    "yyyyMMddHHmmss.0'Z'", System.Globalization.CultureInfo.InvariantCulture));
                break;
            case Array:
                // Value expands arrays before changes reach serialization.
                // Reject nested arrays or arrays added as scalar values rather
                // than silently writing a CLR type name such as System.Int32[].
                throw new ArgumentException("LDAP attribute values cannot be arrays.", nameof(value));
            case IFormattable formattable:
                attribute.Add(formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture));
                break;
            default:
                attribute.Add(value.ToString());
                break;
        }
    }

    private static string FormatDirectoryTime(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return utc.ToString("yyyyMMddHHmmss.0'Z'", System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Re-reads this object's attributes from the server.</summary>
    public void RefreshCache()
    {
        _properties = null;
        _objectSecurity = null;
        _objectSecurityChanged = false;
        EnsureLoaded();
    }

    /// <summary>
    /// Atomically reloads a newly added entry. If the follow-up base search
    /// does not return the object, throws without replacing the add-request cache.
    /// </summary>
    internal void RefreshCacheAfterCreate()
    {
        var refreshed = ReadProperties(
            new[] { "*", "nTSecurityDescriptor" },
            loadDefaultProperties: true);
        if (refreshed.Count == 0)
        {
            throw new DirectoryServicesCOMException(
                "The newly created directory entry could not be read back from the directory.");
        }

        _properties = refreshed;
        _objectSecurity = null;
        _objectSecurityChanged = false;
    }

    /// <summary>Re-reads the specified attributes into the local property cache.</summary>
    public void RefreshCache(string[] propertyNames)
    {
        // ADSI dereferences the array before validating it.
        _ = propertyNames.Length;
        if (propertyNames.Any(propertyName => propertyName is null))
        {
            throw new COMException("The requested property name is invalid.");
        }

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

        }

        foreach (var property in (IEnumerable<PropertyValueCollection>)refreshed)
        {
            // ADSI does not expose a literal ranged request through its managed
            // PropertyCollection. Keep an already cached base property intact.
            if (HasRangeSpecifier(property.PropertyName)
                && propertyNames.Any(HasRangeSpecifier))
            {
                continue;
            }

            properties.ReplaceLoaded(property.PropertyName, property);
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
        catch (DirectoryServicesCOMException ex)
            when (ex.ErrorCode == unchecked((int)0x80072030))
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

    /// <summary>
    /// Moves this entry beneath <paramref name="newParent"/> when both entries use
    /// the same LDAP server and connection settings.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// The source and destination use different LDAP connection contexts. LDAP
    /// ModifyDN cannot perform a cross-server move, so no request is sent.
    /// </exception>
    public void MoveTo(DirectoryEntry newParent)
    {
        ArgumentNullException.ThrowIfNull(newParent);
        EnsureSameMoveConnectionContext(newParent);
        MoveOrRename(newParent.DistinguishedName, LdapDistinguishedName.RelativeName(_path.DistinguishedName));
    }

    /// <summary>
    /// Moves this entry beneath <paramref name="newParent"/> and renames it when
    /// both entries use the same LDAP server and connection settings.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// The source and destination use different LDAP connection contexts. LDAP
    /// ModifyDN cannot perform a cross-server move, so no request is sent.
    /// </exception>
    public void MoveTo(DirectoryEntry newParent, string newName)
    {
        ArgumentNullException.ThrowIfNull(newParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        EnsureSameMoveConnectionContext(newParent);
        MoveOrRename(newParent.DistinguishedName, newName);
    }

    /// <summary>
    /// Creates a managed copy beneath <paramref name="newParent"/>. LDAP has no
    /// copy operation, so client-writable attributes are read and sent in a new
    /// Add request instead.
    /// </summary>
    public DirectoryEntry CopyTo(DirectoryEntry newParent) => CopyTo(newParent, Name);

    /// <inheritdoc cref="CopyTo(DirectoryEntry)"/>
    public DirectoryEntry CopyTo(DirectoryEntry newParent, string newName)
    {
        ArgumentNullException.ThrowIfNull(newParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        ThrowIfDisposed();
        newParent.ThrowIfDisposed();

        var schemaClassName = SchemaClassName
            ?? throw new InvalidOperationException("The source entry does not expose a schema class.");
        var sourceProperties = Properties.Cast<PropertyValueCollection>().ToArray();
        var writable = LdapAttributeSchema.WritableOnAdd(
            newParent.GetSchemaConnection(),
            sourceProperties.Select(property => property.PropertyName));
        var sourceRdnAttribute = RdnAttributeName(Name);
        var destinationRdnAttribute = RdnAttributeName(newName);

        var copy = newParent.Children.Add(newName, schemaClassName);
        try
        {
            foreach (var property in sourceProperties)
            {
                if (property.Count == 0
                    || !writable.Contains(property.PropertyName)
                    || IsCopyManagedAttribute(property.PropertyName, sourceRdnAttribute, destinationRdnAttribute))
                {
                    continue;
                }

                copy.Properties[property.PropertyName].Value = property.Value;
            }

            var sourceSamAccountName = sourceProperties.FirstOrDefault(property =>
                string.Equals(property.PropertyName, "sAMAccountName", StringComparison.OrdinalIgnoreCase));
            if (sourceSamAccountName?.Value is string samAccountName)
            {
                copy.Properties["sAMAccountName"].Value = UniqueCopySamAccountName(samAccountName);
            }

            copy.CommitChanges();
            return copy;
        }
        catch
        {
            copy.Dispose();
            throw;
        }
    }

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

        var response = (SearchResponse)connection.SendRequestCompatible(request);
        var properties = new PropertyCollection(OnPropertyChanged);

        if (response.Entries.Count > 0)
        {
            LoadEntry(response.Entries[0], properties, requestedProperties, loadDefaultProperties);
        }

        return properties;
    }

    private static bool HasRangeSpecifier(string propertyName) =>
        !string.Equals(WithoutRangeSpecifier(propertyName), propertyName, StringComparison.Ordinal);

    private static string WithoutRangeSpecifier(string propertyName) => string.Join(
        ";",
        propertyName.Split(';').Where(part =>
            !part.StartsWith("range=", StringComparison.OrdinalIgnoreCase)));

    private static string EscapeFilterValue(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");

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

    private void LoadEntry(
    SearchResultEntry entry,
    PropertyCollection properties,
    string[] requestedProperties,
    bool normalizeRangedNames)
    {
        foreach (var (name, value) in SearchEntryReader.Read(entry, GetSchemaConnection()))
        {
            var baseName = WithoutRangeSpecifier(name);
            var requestedByBaseName = requestedProperties.Any(requestedName =>
                !HasRangeSpecifier(requestedName)
                && string.Equals(requestedName, baseName, StringComparison.OrdinalIgnoreCase));

            properties.GetOrAdd(
                    normalizeRangedNames || requestedByBaseName ? baseName : name)
                .AddLoaded(value);
        }
    }

    internal LdapConnection GetConnection()
    {
        ThrowIfDisposed();
        return _connection ??= LdapExceptionTranslator.Execute(CreateBoundConnection);
    }

    /// <summary>
    /// Schema discovery uses a dedicated connection so it never attempts a
    /// second request on a connection that is yielding asynchronous results.
    /// </summary>
    internal LdapConnection GetSchemaConnection()
    {
        ThrowIfDisposed();
        return _schemaConnection ??= CreateBoundConnection();
    }

    private LdapConnection CreateBoundConnection()
    {
        var connection = LdapConnectionFactory.CreateBound(BuildOptions());
        try
        {
            LdapConnectionFactory.ConfigureReferralChasing(connection, Options.Referral);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    internal void OnReferralChanged() => ResetConnection();

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
        ThrowIfDisposed();
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

        const AuthenticationTypes supportedAuthenticationTypes =
            AuthenticationTypes.Secure |
            AuthenticationTypes.SecureSocketsLayer |
            AuthenticationTypes.Anonymous |
            AuthenticationTypes.ServerBind |
            AuthenticationTypes.Signing |
            AuthenticationTypes.Sealing;
        var unsupportedAuthenticationTypes = _authenticationType & ~supportedAuthenticationTypes;
        if (unsupportedAuthenticationTypes != 0)
        {
            throw new PlatformNotSupportedException(
                $"AuthenticationTypes value '{unsupportedAuthenticationTypes}' has no faithful " +
                "System.DirectoryServices.Protocols equivalent.");
        }

        var secure = _authenticationType.HasFlag(AuthenticationTypes.Secure);
        var anonymous = _authenticationType.HasFlag(AuthenticationTypes.Anonymous);
        var signing = _authenticationType.HasFlag(AuthenticationTypes.Signing);
        var sealing = _authenticationType.HasFlag(AuthenticationTypes.Sealing);

        if (anonymous && secure)
        {
            throw new PlatformNotSupportedException(
                "AuthenticationTypes.Anonymous cannot be combined with AuthenticationTypes.Secure.");
        }

        if ((signing || sealing) && !secure)
        {
            throw new PlatformNotSupportedException(
                "AuthenticationTypes.Signing and AuthenticationTypes.Sealing require AuthenticationTypes.Secure.");
        }

        var useSsl = _authenticationType.HasFlag(AuthenticationTypes.SecureSocketsLayer)
                     || _path.Port == 636;
        var port = _path.Port ?? (useSsl ? 636 : 389);

        return new LdapConnectionOptions
        {
            Host = _path.Host!,
            Port = port,
            UseSsl = useSsl,
            AuthenticationType = anonymous
                ? AuthType.Anonymous
                : secure ? AuthType.Negotiate : AuthType.Basic,
            Signing = signing,
            Sealing = sealing,
            BindDn = _username,
            BindPassword = _password,
        };
    }

    private void OnPropertyChanged(PropertyValueCollection property)
    {
        ThrowIfDisposed();
        if (_usePropertyCache || _isNew)
        {
            return;
        }

        var request = new ModifyRequest(_path.DistinguishedName);
        AddModifications(request, property);
        GetConnection().SendRequestCompatible(request);
        property.ResetChanged();
    }

    private void EnsureSameMoveConnectionContext(DirectoryEntry newParent)
    {
        var source = BuildOptions();
        var destination = newParent.BuildOptions();

        if (SameHost(source.Host, destination.Host)
            && source.Port == destination.Port
            && source.UseSsl == destination.UseSsl
            && source.UseStartTls == destination.UseStartTls
            && source.SkipCertificateCheck == destination.SkipCertificateCheck
            && source.AuthenticationType == destination.AuthenticationType
            && source.Signing == destination.Signing
            && source.Sealing == destination.Sealing
            && string.Equals(source.BindDn, destination.BindDn, StringComparison.Ordinal)
            && string.Equals(source.BindPassword, destination.BindPassword, StringComparison.Ordinal))
        {
            return;
        }

        throw new PlatformNotSupportedException(
            "DirectoryEntry.MoveTo does not support moving between different LDAP connection contexts. " +
            "Source and destination must use the same server, port, TLS settings, authentication type, " +
            "credentials, and connection security options. No LDAP request was sent.");
    }

    private static bool SameHost(string source, string destination) =>
        string.Equals(
            source.TrimEnd('.'),
            destination.TrimEnd('.'),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsCopyManagedAttribute(
        string attributeName,
        string? sourceRdnAttribute,
        string? destinationRdnAttribute) =>
        string.Equals(attributeName, "objectClass", StringComparison.OrdinalIgnoreCase)
        // Security descriptors carry object-specific ownership and ACL state;
        // do not replay them into a different object context.
        || string.Equals(attributeName, "nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase)
        // Reusing these identity attributes would make an otherwise valid
        // Add fail because AD requires their values to be unique.
        || string.Equals(attributeName, "sAMAccountName", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "userPrincipalName", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "servicePrincipalName", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "dNSHostName", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "msDS-AdditionalSamAccountName", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "msDS-AdditionalDnsHostName", StringComparison.OrdinalIgnoreCase)
        // AD initializes these account-state values and rejects some of them
        // when a client replays values from an existing object in an Add.
        || string.Equals(attributeName, "sAMAccountType", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "pwdLastSet", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "accountExpires", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "countryCode", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "codePage", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "userAccountControl", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, "primaryGroupID", StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, sourceRdnAttribute, StringComparison.OrdinalIgnoreCase)
        || string.Equals(attributeName, destinationRdnAttribute, StringComparison.OrdinalIgnoreCase);

    private static string UniqueCopySamAccountName(string source)
    {
        var computerSuffix = source.EndsWith('$') ? "$" : string.Empty;
        var baseName = computerSuffix.Length == 0 ? source : source[..^1];
        var suffix = $"-{Guid.NewGuid():N}"[..9];
        var maximumBaseLength = 20 - suffix.Length - computerSuffix.Length;
        return string.Concat(baseName.AsSpan(0, Math.Min(baseName.Length, maximumBaseLength)), suffix, computerSuffix);
    }

    private static string? RdnAttributeName(string relativeName)
    {
        var separator = relativeName.IndexOf('=');
        return separator > 0 ? relativeName[..separator].Trim() : null;
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
        GetConnection().SendRequestCompatible(request);
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
        _schemaConnection?.Dispose();
        _schemaConnection = null;
    }

    internal void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    /// <summary>Releases the LDAP connection held by this entry.</summary>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                ResetConnection();
            }

            _properties = null;
            _objectSecurity = null;
            _objectSecurityChanged = false;
            _disposed = true;
        }

        base.Dispose(disposing);
    }
}
