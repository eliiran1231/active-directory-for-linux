namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>
/// The reviewed subset of Microsoft's observable import normalization. This is a detached
/// read projection: the raw descriptor remains the authority for mutation and section intent.
/// Unsupported data is refused, never silently discarded to obtain Microsoft-shaped output.
/// </summary>
internal static class MicrosoftObservableProjector
{
    private const byte Inheritance = 0x03;
    private const byte NoPropagate = 0x04;
    private const byte InheritOnly = 0x08;
    private const byte Inherited = 0x10;

    internal static SecurityDescriptor Project(SecurityDescriptor source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var replacements = new Dictionary<SecurityMasks, byte[]?>();
        foreach (var section in new[] { SecurityMasks.Dacl, SecurityMasks.Sacl })
        {
            var acl = section == SecurityMasks.Dacl ? source.Dacl : source.Sacl;
            if (acl is null) continue;
            var projected = ProjectAcl(acl, section == SecurityMasks.Dacl);
            replacements.Add(section, DescriptorRewriter.EncodeAcl(projected, projected.Aces));
        }

        // Microsoft serializes a clean NULL DACL as absent. This read-only projection
        // never replaces the raw NULL state or creates mutation intent (D14/B6).
        var control = source.DaclState == AclState.Null
            ? (ushort)(source.Control & ~SecurityDescriptor.DaclPresent) : source.Control;
        return DescriptorRewriter.Rewrite(source, control, replacements);
    }

    internal static bool IsUnderstoodAce(Ace ace, bool isDacl)
    {
        var correctKind = isDacl
            ? ace.Kind is AceKind.Access or AceKind.ObjectAccess
            : ace.Kind is AceKind.Audit or AceKind.ObjectAudit;
        var allowedFlags = isDacl ? 0x1f : 0xdf;
        return correctKind && ace.Sid is not null && ace.TrailingLength == 0
            && (ace.AceFlags & ~allowedFlags) == 0 && (ace.ObjectFlags & ~3u) == 0;
    }

    /// <summary>
    /// D13: IO prevents application to this object and the absence of OI/CI prevents propagation.
    /// Clearing IO alone would instead activate the ACE and is never allowed.
    /// </summary>
    internal static bool IsInactiveInheritOnly(Ace ace, bool isDacl) =>
        IsUnderstoodAce(ace, isDacl)
        && (ace.AceFlags & (Inheritance | InheritOnly)) == InheritOnly;

    internal static Acl ProjectAcl(Acl acl, bool isDacl)
    {
        ArgumentNullException.ThrowIfNull(acl);
        if (acl.AclRevision is not (Acl.Revision or Acl.RevisionDS)
            || acl.Sbz1 != 0 || acl.Sbz2 != 0 || !acl.Trailing.IsEmpty)
            throw new InvalidOperationException("Microsoft projection of ACL revision, reserved or trailing data is not validated.");

        var result = new List<Ace>();
        foreach (var ace in acl.Aces)
        {
            if (!IsUnderstoodAce(ace, isDacl))
                throw new InvalidOperationException("Microsoft projection requires a recognized ACE in the correct ACL with validated flags and exact payload size.");
            if (IsInactiveInheritOnly(ace, isDacl)) continue;
            if (ace.AccessMask == 0 || (!isDacl && (ace.AceFlags & 0xC0) == 0))
                throw new InvalidOperationException("Dropping zero-mask or unaudited active ACEs has no reviewed normalization policy.");
            if ((ace.AceFlags & (Inheritance | NoPropagate)) == NoPropagate)
            {
                var bytes = ace.RawBytes.ToArray();
                bytes[1] &= unchecked((byte)~NoPropagate);
                result.Add(Ace.Read(bytes));
            }
            else result.Add(ace);
        }

        // Only partition inside existing explicit qualifier groups. Never move an inherited
        // ACE, cross deny/allow boundaries, or adopt the unresolved SACL sorting behavior.
        if (isDacl)
        {
            for (var start = 0; start < result.Count;)
            {
                if ((result[start].AceFlags & Inherited) != 0) { start++; continue; }
                var deny = IsDeny(result[start]);
                var end = start + 1;
                while (end < result.Count && (result[end].AceFlags & Inherited) == 0
                    && IsDeny(result[end]) == deny) end++;
                var ordered = result.GetRange(start, end - start)
                    .OrderBy(ace => ace.Kind == AceKind.ObjectAccess ? 1 : 0).ToArray();
                for (var i = 0; i < ordered.Length; i++) result[start + i] = ordered[i];
                start = end;
            }
        }

        return Acl.Read(DescriptorRewriter.EncodeAcl(acl, result));
    }

    private static bool IsDeny(Ace ace) => ace.AceType is Ace.AccessDeniedType or Ace.AccessDeniedObjectType;
}
