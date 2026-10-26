using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

internal abstract record LdapMutationCommand(string DistinguishedName, TimeSpan Timeout, LdapTransportControl[] Controls);
internal sealed record LdapAttributeValues(string Name, byte[][] Values);
internal sealed record LdapAddCommand(string DistinguishedName, LdapAttributeValues[] Attributes,
    TimeSpan Timeout, LdapTransportControl[] Controls) : LdapMutationCommand(DistinguishedName, Timeout, Controls);
internal sealed record LdapDeleteCommand(string DistinguishedName, TimeSpan Timeout, LdapTransportControl[] Controls)
    : LdapMutationCommand(DistinguishedName, Timeout, Controls);
internal sealed record LdapModifyDnCommand(string DistinguishedName, string NewRdn, string? NewSuperior,
    bool DeleteOldRdn, TimeSpan Timeout, LdapTransportControl[] Controls) : LdapMutationCommand(DistinguishedName, Timeout, Controls);

// Optional extension: existing Modify-only conversation implementations remain valid.
internal interface ILdapMutationTransport
{
    ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken cancellationToken);
}

internal static class LdapMutationCommands
{
    internal static LdapMutationCommand Prepare(LdapMutationCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        static string Text(string value) => value is null || value.Contains('\0')
            ? throw new ArgumentException("LDAP request strings cannot be null or contain NUL.") : value;
        static byte[][] Values(byte[][] values) => values.Select(value => value.ToArray()).ToArray();
        if (command.Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(command.Timeout));
        var dn = Text(command.DistinguishedName);
        var controls = command.Controls.Select(control => LdapControlCodec.Snapshot(control with { Oid = Text(control.Oid) })).ToArray();
        LdapMutationCommand prepared = command switch
        {
            LdapModifyCommand modify => modify with
            {
                Changes = modify.Changes.Select(change => change.Operation is < DirectoryAttributeOperation.Add or > DirectoryAttributeOperation.Replace
                    ? throw new ArgumentException("Invalid modification operation.")
                    : change with { Name = Text(change.Name), Values = Values(change.Values) }).ToArray()
            },
            LdapAddCommand add => add with
            { Attributes = add.Attributes.Select(attribute => attribute.Values.Length == 0 ? throw new ArgumentException("An Add attribute must contain at least one value.") : attribute with { Name = Text(attribute.Name), Values = Values(attribute.Values) }).ToArray() },
            LdapDeleteCommand delete => delete,
            LdapModifyDnCommand rename => rename with
            { NewRdn = Text(rename.NewRdn), NewSuperior = rename.NewSuperior is null ? null : Text(rename.NewSuperior) },
            _ => throw new ArgumentException("Unknown mutation command.")
        };
        return prepared with { DistinguishedName = dn, Controls = controls };
    }

    internal static void RequireCapabilities(ILdapRequestTransport transport, LdapMutationCommand command)
    {
        var required = command switch
        {
            LdapModifyCommand => LdapTransportCapabilities.Modify,
            LdapAddCommand => LdapTransportCapabilities.Add,
            LdapDeleteCommand => LdapTransportCapabilities.Delete,
            LdapModifyDnCommand => LdapTransportCapabilities.ModifyDn,
            _ => throw new PlatformNotSupportedException("Unknown mutation; no request was sent.")
        };
        if ((transport.Capabilities & required) != required ||
            (transport is not ILdapMutationTransport && (command is not LdapModifyCommand || transport is not ILdapConversationTransport)))
            throw new PlatformNotSupportedException("This transport cannot represent the mutation; no request was sent.");
        // Preserve legacy Modify-only implementations while allowing generic controls.
        if (command.Controls.Length != 0 && (transport.Capabilities & LdapTransportCapabilities.MutationControls) == 0 && (command is not LdapModifyCommand ||
            (transport.Capabilities & LdapTransportCapabilities.ModifyControls) == 0))
            throw new PlatformNotSupportedException("This transport cannot represent the mutation controls; no request was sent.");
    }

    internal static ValueTask<LdapResultEnvelope> SendAsync(ILdapRequestTransport transport, LdapMutationCommand command,
        LdapSubmission submission, CancellationToken cancellationToken)
        => transport is ILdapMutationTransport unified ? unified.MutateAsync(command, submission, cancellationToken)
            : ((ILdapConversationTransport)transport).ModifyAsync((LdapModifyCommand)command, submission, cancellationToken);
}
