using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

[Flags]
internal enum LdapTransportCapabilities { None = 0, Search = 1, SearchControls = 2, ProtocolsConnection = 4, StreamingSearch = 8, PagedSearch = 16, Modify = 32, ModifyControls = 64 }
// Request controls are server-side controls; response controls preserve their wire payload.
internal sealed record LdapTransportControl(string Oid, byte[] Value, bool Critical);
internal sealed record LdapSearchCommand(string BaseDn, string Filter, ProtocolScope Scope,
    string[] Attributes, TimeSpan Timeout, int SizeLimit = 0, bool TypesOnly = false,
    LdapTransportControl[]? Controls = null);
internal sealed record LdapTransportEntry(string DistinguishedName,
    Dictionary<string, byte[][]> Attributes, LdapTransportControl[] Controls);
internal sealed record LdapTransportReference(string[] Urls, LdapTransportControl[] Controls);
internal sealed record LdapSearchResult(ResultCode Code, string? MatchedDn, string? Diagnostic,
    LdapTransportEntry[] Entries, LdapTransportReference[] References, string[] Referrals, LdapTransportControl[] Controls);

// Borrowed only for the enclosing session lease. Responses own managed copies;
// no LDAPMessage, native callback buffer or Protocols private handle may escape.
internal interface ILdapRequestTransport
{
    LdapTransportCapabilities Capabilities { get; }
    TimeSpan Timeout { get; }
    string? ConnectedHost { get; }
    LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken);
}

internal static class LdapRequestDispatcher
{
    internal static LdapSearchResult Search(ILdapRequestTransport transport, LdapSearchCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return transport.Search(Prepare(transport, command), cancellationToken);
    }

    internal static LdapSearchCommand Prepare(ILdapRequestTransport transport, LdapSearchCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        static void Text(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Contains('\0')) throw new ArgumentException("LDAP request strings cannot contain NUL.");
        }
        Text(command.BaseDn); Text(command.Filter);
        ArgumentNullException.ThrowIfNull(command.Attributes);
        var attributes = command.Attributes.ToArray();
        foreach (var attribute in attributes) Text(attribute);
        if (command.Scope is < ProtocolScope.Base or > ProtocolScope.Subtree || command.SizeLimit < 0 ||
            command.Timeout < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(command));
        var controls = (command.Controls ?? []).Select(control =>
        {
            Text(control.Oid);
            return control with { Value = control.Value.ToArray() };
        }).ToArray();
        var required = LdapTransportCapabilities.Search |
            (controls.Length == 0 ? LdapTransportCapabilities.None : LdapTransportCapabilities.SearchControls);
        if ((transport.Capabilities & required) != required)
            throw new PlatformNotSupportedException("The transport cannot represent the complete request; no request was sent.");
        // Snapshot and check the complete request before any dispatch.
        return command with { Attributes = attributes, Controls = controls };
    }
}

internal sealed class ProtocolsLdapTransport(LdapConnection connection) : ILdapRequestTransport
{
    public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
        LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.ProtocolsConnection;
    public TimeSpan Timeout => connection.Timeout;
    public string? ConnectedHost => LdapExceptionTranslator.Execute(() => connection.SessionOptions.HostName);
    public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = new SearchRequest(command.BaseDn, command.Filter, command.Scope, command.Attributes)
        { SizeLimit = command.SizeLimit, TypesOnly = command.TypesOnly };
        foreach (var control in command.Controls ?? [])
            request.Controls.Add(new DirectoryControl(control.Oid, control.Value, control.Critical, true));
        // Preserve the existing synchronous Protocols behavior/exception mapping.
        // Cancellation during that call is cooperative, not a hard interrupt.
        var response = command.Timeout == connection.Timeout
            ? (SearchResponse)connection.SendRequestCompatible(request)
            : LdapExceptionTranslator.Execute(() =>
            {
                try { return (SearchResponse)connection.SendRequest(request, command.Timeout); }
                catch (Exception error) { LdapConnectionProvider.ReportFailure(connection, error); throw; }
            });
        cancellationToken.ThrowIfCancellationRequested();
        static LdapTransportControl[] Controls(DirectoryControl[] controls) => controls.Select(c =>
            new LdapTransportControl(c.Type, c.GetValue(), c.IsCritical)).ToArray();
        var entries = response.Entries.Cast<SearchResultEntry>().Select(entry =>
        {
            var values = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in entry.Attributes.AttributeNames)
                values.Add(name, entry.Attributes[name].GetValues(typeof(byte[])).Cast<byte[]>().Select(v => v.ToArray()).ToArray());
            return new LdapTransportEntry(entry.DistinguishedName, values, Controls(entry.Controls));
        }).ToArray();
        return new LdapSearchResult(response.ResultCode, response.MatchedDN, response.ErrorMessage, entries,
            response.References.Cast<SearchResultReference>().Select(r =>
                new LdapTransportReference(r.Reference.Select(uri => uri.ToString()).ToArray(), Controls(r.Controls))).ToArray(),
            response.Referral.Select(uri => uri.ToString()).ToArray(), Controls(response.Controls));
    }
}
