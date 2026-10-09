#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using WireMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace AdForLinux.Security.AccessControl;

// Staged preparation only. DirectoryEntry's BCL-rooted persistence path is not wired
// to this until the coordinated AD/rule cutover and validated implementation of the
// approved persistence contracts (see issue-226-persistence-decisions.md).
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

    internal static void ValidateAddDescriptor(byte[]? explicitDescriptor)
    {
        if (explicitDescriptor is not null)
            throw new NotSupportedException("LDAP Add ignores SD-flags scoping; explicit descriptor creation requires a validated raw-safe implementation.");
        // No explicit descriptor: omit the attribute and let the server create it.
    }
}
