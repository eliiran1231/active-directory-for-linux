using System.DirectoryServices.Protocols;
using System.Runtime.CompilerServices;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Resolves Active Directory attribute syntaxes and caches them for the life
/// of an LDAP connection. Attribute names are not sufficient to determine
/// their wire representation because administrators can extend the schema.
/// </summary>
internal static class LdapAttributeSchema
{
    private static readonly ConditionalWeakTable<LdapConnection, SchemaCache> Caches = new();

    // Preserve the safe behavior for common binary attributes if a non-AD
    // server does not publish schemaNamingContext or the requested schema row.
    private static readonly HashSet<string> BinaryFallback = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectGUID", "objectSid", "sIDHistory", "mS-DS-ConsistencyGuid",
        "msDS-ConsistencyGuid", "schemaIDGUID", "attributeSecurityGUID",
        "nTSecurityDescriptor", "thumbnailPhoto", "jpegPhoto", "photo",
        "userCertificate", "userSMIMECertificate", "cACertificate", "tokenGroups",
        "tokenGroupsGlobalAndUniversal", "logonHours", "msExchMailboxGuid",
    };

    public static IReadOnlyDictionary<string, LdapValueKind> Resolve(
        LdapConnection connection,
        IEnumerable<string> attributeNames)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(attributeNames);
        return Caches.GetValue(connection, static connection => new SchemaCache(connection))
            .Resolve(attributeNames);
    }

    public static LdapValueKind BinaryFallbackFor(string attributeName) =>
        BinaryFallback.Contains(CanonicalName(attributeName))
            ? LdapValueKind.Binary
            : LdapValueKind.String;

    /// <summary>
    /// Returns the attributes that can safely be supplied by a client in an
    /// LDAP Add request. Unknown attributes remain eligible so this also works
    /// with generic LDAP servers and custom schemas.
    /// </summary>
    public static IReadOnlySet<string> WritableOnAdd(
        LdapConnection connection,
        IEnumerable<string> attributeNames)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(attributeNames);
        return Caches.GetValue(connection, static connection => new SchemaCache(connection))
            .WritableOnAdd(attributeNames);
    }

    /// <summary>
    /// Verifies that an AD attribute has the Object(DS-DN) schema syntax required
    /// by attribute-scoped queries: attributeSyntax 2.5.5.1 and oMSyntax 127.
    /// </summary>
    public static void EnsureDistinguishedNameAttribute(LdapConnection connection, string attributeName)
    {
        var rootDse = RootDse.Read(connection, "schemaNamingContext");
        if (!rootDse.TryGetValue("schemaNamingContext", out var schemaNamingContext) ||
            string.IsNullOrEmpty(schemaNamingContext))
        {
            throw InvalidAttributeSyntax(attributeName, "the server did not expose schemaNamingContext");
        }

        var request = new SearchRequest(
            schemaNamingContext,
            $"(&(objectClass=attributeSchema)(lDAPDisplayName={EscapeFilterValue(attributeName)}))",
            ProtocolScope.OneLevel,
            "attributeSyntax",
            "oMSyntax");
        var response = (SearchResponse)connection.SendRequestCompatible(request);

        if (response.Entries.Count != 1)
        {
            throw InvalidAttributeSyntax(attributeName, "no matching attributeSchema object was found");
        }

        var entry = response.Entries[0];
        var attributeSyntax = FirstString(entry, "attributeSyntax");
        var omSyntax = FirstString(entry, "oMSyntax");
        if (!string.Equals(attributeSyntax, "2.5.5.1", StringComparison.Ordinal) ||
            !string.Equals(omSyntax, "127", StringComparison.Ordinal))
        {
            throw InvalidAttributeSyntax(
                attributeName,
                $"schema syntax was attributeSyntax={attributeSyntax ?? "<missing>"}, " +
                $"oMSyntax={omSyntax ?? "<missing>"}, not Object(DS-DN)");
        }
    }

    internal static LdapValueKind KindFromSyntax(string? attributeSyntax, string? omSyntax) =>
        (attributeSyntax, omSyntax) switch
        {
            ("2.5.5.8", "1") => LdapValueKind.Boolean,
            ("2.5.5.9", "2" or "10") => LdapValueKind.Int32,
            ("2.5.5.16", "65") => LdapValueKind.Int64,
            ("2.5.5.11", "23" or "24") => LdapValueKind.DateTime,
            ("2.5.5.10", _) or ("2.5.5.15", "66") or ("2.5.5.17", "4") =>
                LdapValueKind.Binary,
            _ => LdapValueKind.String,
        };

    private static string CanonicalName(string attributeName)
    {
        var option = attributeName.IndexOf(';');
        return option < 0 ? attributeName : attributeName[..option];
    }

    private static string? FirstString(SearchResultEntry entry, string attributeName)
    {
        var attribute = entry.Attributes[attributeName];
        return attribute?.Count > 0
            ? attribute.GetValues(typeof(string)).Cast<string>().FirstOrDefault()
            : null;
    }

    private static DirectoryServicesCOMException InvalidAttributeSyntax(string attributeName, string reason) =>
        LdapExceptionTranslator.Translate(
            ResultCode.InvalidAttributeSyntax,
            $"AttributeScopeQuery attribute '{attributeName}' is invalid: {reason}. " +
            "LDAP invalidAttributeSyntax (21).");

    private static string EscapeFilterValue(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");

    private sealed class SchemaCache
    {
        private readonly LdapConnection _connection;
        private readonly Dictionary<string, LdapValueKind> _kinds =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, bool> _writableOnAdd =
            new(StringComparer.OrdinalIgnoreCase);
        private string? _schemaNamingContext;
        private bool _schemaUnavailable;

        public SchemaCache(LdapConnection connection) => _connection = connection;

        public IReadOnlyDictionary<string, LdapValueKind> Resolve(IEnumerable<string> attributeNames)
        {
            var names = attributeNames
                .Select(CanonicalName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            lock (_kinds)
            {
                var missing = names.Where(name => !_kinds.ContainsKey(name)).ToArray();
                if (missing.Length > 0)
                {
                    Load(missing);
                }

                return names.ToDictionary(
                    name => name,
                    name => _kinds[name],
                    StringComparer.OrdinalIgnoreCase);
            }
        }

        public IReadOnlySet<string> WritableOnAdd(IEnumerable<string> attributeNames)
        {
            var names = attributeNames
                .Select(CanonicalName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            lock (_kinds)
            {
                var missing = names.Where(name => !_writableOnAdd.ContainsKey(name)).ToArray();
                if (missing.Length > 0)
                {
                    LoadWritableOnAdd(missing);
                }

                return names
                    .Where(name => _writableOnAdd[name])
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
        }

        private void Load(string[] names)
        {
            if (!_schemaUnavailable)
            {
                try
                {
                    _schemaNamingContext ??= ReadSchemaNamingContext();
                    if (!string.IsNullOrEmpty(_schemaNamingContext))
                    {
                        var nameFilter = names.Length == 1
                            ? $"(lDAPDisplayName={EscapeFilterValue(names[0])})"
                            : $"(|{string.Concat(names.Select(name => $"(lDAPDisplayName={EscapeFilterValue(name)})"))})";
                        var request = new SearchRequest(
                            _schemaNamingContext,
                            $"(&(objectClass=attributeSchema){nameFilter})",
                            ProtocolScope.OneLevel,
                            "lDAPDisplayName",
                            "attributeSyntax",
                            "oMSyntax");
                        var response = (SearchResponse)_connection.SendRequest(request);
                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            var name = FirstString(entry, "lDAPDisplayName");
                            if (!string.IsNullOrEmpty(name))
                            {
                                _kinds[name] = KindFromSyntax(
                                    FirstString(entry, "attributeSyntax"),
                                    FirstString(entry, "oMSyntax"));
                            }
                        }
                    }
                    else
                    {
                        _schemaUnavailable = true;
                    }
                }
                catch (Exception error) when (error is LdapException or DirectoryOperationException)
                {
                    // Generic LDAP servers need not expose AD's schema partition.
                    _schemaUnavailable = true;
                }
            }

            foreach (var name in names)
            {
                _kinds.TryAdd(name, BinaryFallbackFor(name));
            }
        }

        private void LoadWritableOnAdd(string[] names)
        {
            foreach (var name in names)
            {
                // Unknown attributes remain eligible for generic LDAP servers
                // and custom schemas unless schema metadata says otherwise.
                _writableOnAdd.TryAdd(name, true);
            }

            if (_schemaUnavailable)
            {
                return;
            }

            try
            {
                _schemaNamingContext ??= ReadSchemaNamingContext();
                if (string.IsNullOrEmpty(_schemaNamingContext))
                {
                    _schemaUnavailable = true;
                    return;
                }

                var nameFilter = names.Length == 1
                    ? $"(lDAPDisplayName={EscapeFilterValue(names[0])})"
                    : $"(|{string.Concat(names.Select(name => $"(lDAPDisplayName={EscapeFilterValue(name)})"))})";
                var request = new SearchRequest(
                    _schemaNamingContext,
                    $"(&(objectClass=attributeSchema){nameFilter})",
                    ProtocolScope.OneLevel,
                    "lDAPDisplayName",
                    "systemOnly",
                    "systemFlags");
                var response = (SearchResponse)_connection.SendRequest(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var name = FirstString(entry, "lDAPDisplayName");
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    var systemOnly = string.Equals(
                        FirstString(entry, "systemOnly"),
                        "TRUE",
                        StringComparison.OrdinalIgnoreCase);
                    _ = int.TryParse(FirstString(entry, "systemFlags"), out var systemFlags);
                    const int serverManagedFlags = 0x1 | 0x4 | 0x8;
                    _writableOnAdd[name] = !systemOnly && (systemFlags & serverManagedFlags) == 0;
                }
            }
            catch (Exception error) when (error is LdapException or DirectoryOperationException)
            {
                // LDAP servers are not required to publish an Active Directory
                // schema partition. Avoid repeating a lookup that cannot work.
                _schemaUnavailable = true;
            }
        }

        private string? ReadSchemaNamingContext()
        {
            var rootDse = RootDse.Read(_connection, "schemaNamingContext");
            return rootDse.TryGetValue("schemaNamingContext", out var value) ? value : null;
        }
    }
}

internal enum LdapValueKind
{
    String,
    Binary,
    Boolean,
    Int32,
    Int64,
    DateTime,
}
