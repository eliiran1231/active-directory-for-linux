using System.DirectoryServices.Protocols;
using System.Runtime.CompilerServices;
using System.Text;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class LdapAttributeSchema
{
    // Key by the persistent resource, never endpoint/principal or a checkout.
    // Keep the existing Protocols cache/exception behavior unchanged.
    private static readonly ConditionalWeakTable<ILdapRequestTransport, TransportSchemaCache> TransportCaches = new();
    internal static IReadOnlyDictionary<string, LdapValueKind> Resolve(
        ILdapRequestTransport transport, IEnumerable<string> attributeNames,
        Func<TimeSpan>? remaining = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(attributeNames);
        return TransportCaches.GetValue(transport, static resource => new(resource)).Resolve(attributeNames, remaining, cancellationToken);
    }

    private sealed class TransportSchemaCache(ILdapRequestTransport transport)
    {
        private readonly Dictionary<string, LdapValueKind> kinds = new(StringComparer.OrdinalIgnoreCase);
        private string? schemaNamingContext;
        private bool schemaUnavailable;
        internal IReadOnlyDictionary<string, LdapValueKind> Resolve(IEnumerable<string> attributeNames,
            Func<TimeSpan>? remaining, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TimeSpan Budget()
            {
                cancellationToken.ThrowIfCancellationRequested();
                var value = remaining?.Invoke() ?? transport.Timeout;
                return value > TimeSpan.Zero ? value : throw new TimeoutException("Schema operation deadline expired.");
            }
            var names = attributeNames.Select(CanonicalName).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            lock (kinds)
            {
                Budget();
                var cacheMissing = true;
                var missing = names.Where(name => !kinds.ContainsKey(name)).ToArray();
                if (missing.Length != 0 && !schemaUnavailable)
                {
                    // RootDSE failures propagate, as on the existing Protocols path.
                    if (schemaNamingContext is null)
                    {
                        var root = RootDse.Read(transport, Budget(), cancellationToken, "schemaNamingContext");
                        if (!root.TryGetValue("schemaNamingContext", out schemaNamingContext) || string.IsNullOrEmpty(schemaNamingContext))
                            schemaUnavailable = true;
                    }
                    if (!schemaUnavailable)
                    {
                        var filter = missing.Length == 1 ? $"(lDAPDisplayName={EscapeFilterValue(missing[0])})"
                            : $"(|{string.Concat(missing.Select(name => $"(lDAPDisplayName={EscapeFilterValue(name)})"))})";
                        var response = LdapRequestDispatcher.Search(transport, new(schemaNamingContext!,
                            $"(&(objectClass=attributeSchema){filter})", ProtocolScope.OneLevel,
                            ["lDAPDisplayName", "attributeSyntax", "oMSyntax"], Budget()), cancellationToken);
                        Budget(); // reject late completion against the same operation budget
                        // Explicit LDAP schema-query failures permit the existing non-AD
                        // fallback. Unknown transport/decoding failures are not hidden.
                        if (response.Code is ResultCode.Unavailable or ResultCode.ProtocolError)
                            throw LdapExceptionTranslator.Translate(response.Code, response.Diagnostic ?? "Schema connection failed.");
                        cacheMissing = response.References.Length == 0 && response.Referrals.Length == 0;
                        if (response.Code != ResultCode.Success) schemaUnavailable = true;
                        else foreach (var entry in response.Entries)
                        {
                            var name = FirstString(entry, "lDAPDisplayName");
                            if (!string.IsNullOrEmpty(name)) kinds[name] = KindFromSyntax(
                                FirstString(entry, "attributeSyntax"), FirstString(entry, "oMSyntax"));
                        }
                    }
                }
                // Preserve current fallback values for incomplete results, without
                // permanently caching absence when a reference may hold the row.
                if (cacheMissing) foreach (var name in names) kinds.TryAdd(name, BinaryFallbackFor(name));
                Budget();
                return names.ToDictionary(name => name, name => kinds.TryGetValue(name, out var kind) ? kind : BinaryFallbackFor(name), StringComparer.OrdinalIgnoreCase);
            }
        }
        private static string? FirstString(LdapTransportEntry entry, string name) =>
            entry.Attributes.TryGetValue(name, out var values) && values.Length != 0
                ? Encoding.UTF8.GetString(values[0]) : null;
    }
}
