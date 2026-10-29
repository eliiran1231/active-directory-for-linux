using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    internal sealed partial class ConnectionLease
    {
        // Borrow the enclosing lease, preserving the original Protocols request
        // (including controls and metadata) rather than reconstructing it.
        internal BorrowedSearchResult Search(SearchRequest request, Func<TimeSpan>? remaining = null,
            CancellationToken cancellationToken = default) => ExecuteTransport(transport =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var timeout = remaining?.Invoke() ?? transport.Timeout;
            LdapSearchResult result;
            SearchResponse? original = null;
            if ((transport.Capabilities & LdapTransportCapabilities.ProtocolsConnection) != 0)
            {
                original = (SearchResponse)Connection.SendRequestCompatible(request);
                result = ProtocolsLdapTransport.Map(original);
            }
            else
            {
                result = LdapRequestDispatcher.Search(transport,
                    LdapRequestDispatcher.FromRequest(transport, request, timeout), cancellationToken);
                if (result.Code != ResultCode.Success)
                    throw LdapExceptionTranslator.Translate(result.Code, result.Diagnostic ?? "LDAP search failed.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (remaining is not null)
            {
                var after = remaining();
                if (original is null && after <= TimeSpan.Zero) throw new TimeoutException("LDAP read deadline expired.");
            }
            return new BorrowedSearchResult(result, original);
        });

        internal object[] ReadValues(DirectoryEntry owner, string attributeName, byte[][] values, DirectoryAttribute? original,
            Func<TimeSpan> remaining) => ExecuteTransport(transport =>
        {
            // Retained Protocols schema transports keep their existing CWT key.
            var kind = (transport.Capabilities & LdapTransportCapabilities.ProtocolsConnection) != 0
                ? LdapAttributeSchema.Resolve(owner.SchemaConnectionForOperation(Connection), [attributeName])[attributeName]
                : LdapAttributeSchema.Resolve(transport, [attributeName], remaining)[attributeName];
            if (original is not null)
            {
                remaining();
                var wanted = kind == LdapValueKind.Binary ? typeof(byte[]) : typeof(string);
                return original.GetValues(wanted).Select(value => SearchEntryReader.ConvertValue(value, kind)).ToArray();
            }
            return values.Select(bytes =>
            {
                if (remaining() <= TimeSpan.Zero) throw new TimeoutException("LDAP value conversion deadline expired.");
                return kind == LdapValueKind.Binary ? bytes.ToArray() : SearchEntryReader.ConvertValue(Encoding.UTF8.GetString(bytes), kind);
            }).ToArray();
        });
    }
    internal sealed class BorrowedSearchResult(LdapSearchResult result, SearchResponse? original)
    {
        internal LdapTransportEntry[] Entries => result.Entries;
        internal ResultCode Code => result.Code;
        internal LdapSearchResult Envelope => result;
        internal DirectoryAttribute? OriginalAttribute(string name) => original?.Entries[0].Attributes[name];
        internal byte[]? FirstBinary(string name)
        {
            if (Entries.Length == 0) return null;
            if (original is not null)
                return original.Entries[0].Attributes[name] is { Count: > 0 } attribute && attribute[0] is byte[] bytes ? bytes.ToArray() : null;
            return Entries[0].Attributes.TryGetValue(name, out var values) && values.Length != 0 ? values[0].ToArray() : null;
        }
    }

}
