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
        var normalized = NormalizeForEdit(acl, isDacl);
        // Import can compact explicit ACEs even though a live Microsoft ACL can retain
        // the same pair after split-then-restore. This boundary belongs only to detached
        // read/import projection; applying it during edits would reject recorded live states.
        if (!isDacl || HasCanonicalQualifierOrder(normalized.Aces))
        {
            for (var i = 0; i < normalized.Aces.Count; i++)
            for (var j = i + 1; j < normalized.Aces.Count; j++)
            {
                var a = normalized.Aces[i];
                var b = normalized.Aces[j];
                if (a.Kind is not (AceKind.Access or AceKind.Audit)
                    || a.AceType != b.AceType || !a.Sid!.Equals(b.Sid)
                    || ((a.AceFlags | b.AceFlags) & Inherited) != 0
                    || (a.AceFlags & 0xc0) != (b.AceFlags & 0xc0)) continue;
                var aScope = a.AceFlags & 0x0f;
                var bScope = b.AceFlags & 0x0f;
                if (aScope == bScope || (a.AccessMask == b.AccessMask
                    && ((aScope == 0 && bScope == 10) || (aScope == 10 && bScope == 0))))
                    throw new InvalidOperationException("Microsoft import compaction of compatible explicit ACEs is not approved.");
            }
        }
        return normalized;
    }

    // Reviewed D13 normalization used by the live mutation engine, independently of
    // whether a fresh Microsoft import could compact that engine's current ACE list.
    internal static Acl NormalizeForEdit(Acl acl, bool isDacl)
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

        if (isDacl && !HasCanonicalQualifierOrder(result))
        {
            // G: Microsoft leaves a known noncanonical ACL in its original order. Do not
            // apply the canonical object partition to such a list. Mixed normalization of
            // noncanonical input is not independently established by these recordings.
            if (result.Count != acl.Aces.Count
                || result.Where((ace, index) => !ace.RawBytes.SequenceEqual(acl.Aces[index].RawBytes)).Any())
                throw new InvalidOperationException("Normalization of a noncanonical DACL is not validated.");
            return acl;
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

        RefuseUnreviewedExplicitOrdering(result, isDacl);
        return Acl.Read(DescriptorRewriter.EncodeAcl(acl, result));
    }

    private static void RefuseUnreviewedExplicitOrdering(IReadOnlyList<Ace> aces, bool isDacl)
    {
        Ace? previous = null;
        var previousGroup = -1;
        foreach (var ace in aces)
        {
            // Inherited order belongs to the parent and is never sorted by this projector.
            if ((ace.AceFlags & Inherited) != 0) { previous = null; previousGroup = -1; continue; }
            var objectAce = ace.Kind is AceKind.ObjectAccess or AceKind.ObjectAudit;
            var group = (isDacl && !IsDeny(ace) ? 2 : 0) + (objectAce ? 1 : 0);
            if (!isDacl && group < previousGroup)
                throw new InvalidOperationException("Microsoft SACL object-family reordering is not approved.");
            if (previous is not null && group == previousGroup && CompareSid(previous.Sid!, ace.Sid!) > 0)
                throw new InvalidOperationException("Microsoft explicit-subgroup SID reordering is not approved.");
            previous = ace;
            previousGroup = group;
        }
    }

    private static int CompareSid(Sid left, Sid right)
    {
        var comparison = left.IdentifierAuthority.CompareTo(right.IdentifierAuthority);
        if (comparison != 0) return comparison;
        comparison = left.SubAuthorityCount.CompareTo(right.SubAuthorityCount);
        if (comparison != 0) return comparison;
        for (var index = 0; index < left.SubAuthorityCount; index++)
        {
            comparison = left.GetSubAuthority(index).CompareTo(right.GetSubAuthority(index));
            if (comparison != 0) return comparison;
        }
        return left.SubAuthorityCount.CompareTo(right.SubAuthorityCount);
    }

    private static bool HasCanonicalQualifierOrder(IReadOnlyList<Ace> aces)
    {
        var previous = -1;
        foreach (var ace in aces)
        {
            var group = (ace.AceFlags & Inherited) != 0 ? 2 : IsDeny(ace) ? 0 : 1;
            if (group < previous) return false;
            previous = group;
        }
        return true;
    }

    private static bool IsDeny(Ace ace) => ace.AceType is Ace.AccessDeniedType or Ace.AccessDeniedObjectType;
}
