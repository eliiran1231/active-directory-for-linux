#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using WireMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace AdForLinux.Security.AccessControl;

// Immutable raw request plan bound to the descriptor and destination read generation.
internal sealed class PreparedRawSecurityWrite
{
    private readonly byte[] bytes;
    internal EntryMasks Sections { get; }
    internal ObjectSecurity.IdentityRead Read { get; }
    internal object WrapperToken { get; }
    internal PreparedRawSecurityWrite(byte[] bytes, EntryMasks sections, ObjectSecurity.IdentityRead read, object wrapperToken)
    { this.bytes = (byte[])bytes.Clone(); Sections = sections; Read = read; WrapperToken = wrapperToken; }
    internal byte[] GetBinaryForm() => (byte[])bytes.Clone();
}

internal static class RawSecurityWritePreparation
{
    // These enums do not share bit positions: Access=2, Audit=1, Owner=4, Group=8.
    internal static EntryMasks Masks(AccessControlSections sections)
    {
        if ((sections & ~AccessControlSections.All) != 0) throw new ArgumentOutOfRangeException(nameof(sections));
        return ((sections & AccessControlSections.Owner) != 0 ? EntryMasks.Owner : 0)
            | ((sections & AccessControlSections.Group) != 0 ? EntryMasks.Group : 0)
            | ((sections & AccessControlSections.Access) != 0 ? EntryMasks.Dacl : 0)
            | ((sections & AccessControlSections.Audit) != 0 ? EntryMasks.Sacl : 0);
    }

    internal static PreparedRawSecurityWrite PrepareModify(ObjectSecurity security, EntryMasks selectedSections)
    {
        var read = security.CaptureIdentityRead();
        if (read.Resolver is null) throw new InvalidOperationException("Raw write preparation requires an explicit current entry context.");
        return security.ValidateIdentityRead(read, () =>
        {
            if (!security.HasRawReadContext) throw new InvalidOperationException("Detached data has no destination read baseline.");
            if (security.RawReadOrigin != read.Resolver.GetReadOrigin()) throw new InvalidOperationException("The read baseline belongs to a different entry or binding generation.");
            var changed = security._securityDescriptor.ChangesSince(security.ReadVersion);
            if ((changed & ~security.RetrievedSections) != 0) throw new InvalidOperationException("An edited section was not retrieved.");
            if (selectedSections != changed) throw new InvalidOperationException("The explicit write selection must account for all pending sections without widening it.");
            var state = security._securityDescriptor.MutationState;
            var raw = state.Descriptor.GetBinaryForm();
            if (raw.AsSpan().SequenceEqual(security.OriginalReadSnapshot!.GetBinaryForm())) changed = EntryMasks.None;
            return new PreparedRawSecurityWrite(raw, changed, read, security);
        });
    }

    internal static void AppendModify(ObjectSecurity security, PreparedRawSecurityWrite plan, ModifyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!ReferenceEquals(plan.WrapperToken, security)) throw new InvalidOperationException("The write plan belongs to a different wrapper.");
        security.ValidateIdentityRead(plan.Read, () =>
        {
            if (security.RawReadOrigin != plan.Read.Resolver!.GetReadOrigin()
                || !string.Equals(request.DistinguishedName, security.RawReadOrigin.DistinguishedName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The request does not target the entry and generation that supplied the read baseline.");
            if (plan.Sections == EntryMasks.None) return true;
            if (request.Modifications.Cast<DirectoryAttributeModification>().Any(m => m.Name.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase))
                || request.Controls.Cast<DirectoryControl>().Any(c => c.Type == "1.2.840.113556.1.4.801"))
                throw new InvalidOperationException("The request already contains a security descriptor or mask control.");
            var modification = new DirectoryAttributeModification { Name = "nTSecurityDescriptor", Operation = DirectoryAttributeOperation.Replace };
            modification.Add(plan.GetBinaryForm());
            request.Modifications.Add(modification);
            request.Controls.Add(new SecurityDescriptorFlagControl((WireMasks)(int)plan.Sections));
            return true;
        });
    }

    internal static byte[]? PrepareAdd(byte[]? explicitDescriptor, EntryMasks known)
    {
        if (explicitDescriptor is null) return null;
        const EntryMasks all = EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl;
        if (known != all) throw new NotSupportedException("Creation requires explicit knowledge of every descriptor section.");
        var raw = AdForLinux.DirectoryServices.Security.Core.SecurityDescriptor.Parse(explicitDescriptor, known);
        // Complete protected input can be transmitted without inventing default or
        // inheritance semantics. Broader explicit creation remains a validation gap.
        if (raw.Owner is null || raw.Group is null || raw.Dacl is null || raw.Sacl is null || (raw.Control & 0x3000) != 0x3000)
            throw new NotSupportedException("Explicit creation with omitted, NULL or inheriting sections awaits validated server-default semantics.");
        return raw.GetBinaryForm();
    }

    internal static void AppendAdd(AddRequest request, byte[]? explicitDescriptor, EntryMasks known)
    {
        ArgumentNullException.ThrowIfNull(request);
        var bytes = PrepareAdd(explicitDescriptor, known);
        if (request.Attributes.Cast<DirectoryAttribute>().Any(a => a.Name.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase))
            || request.Controls.Cast<DirectoryControl>().Any(c => c.Type == "1.2.840.113556.1.4.801"))
            throw new InvalidOperationException("Creation already contains untracked descriptor data or a Modify-only security mask.");
        if (bytes is not null) request.Attributes.Add(new DirectoryAttribute("nTSecurityDescriptor", bytes));
    }
}
