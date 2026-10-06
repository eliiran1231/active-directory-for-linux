using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

internal enum AclModification { Add, Set, Reset, Remove, RemoveSpecific, RemoveAll }

/// <summary>Microsoft operation evidence and portable write intent are deliberately separate.</summary>
internal sealed record AclMutationResult(AclMutationEngine Engine, bool ReturnValue, bool Modified);

/// <summary>
/// Immutable, detached edit planner. It never performs identity resolution or directory I/O.
/// The original raw value remains available even after absent/NULL DACL materialization.
/// Unsupported interpretation or movement refuses the complete operation.
/// </summary>
internal sealed class AclMutationEngine
{
    private const uint ObjectQualifiedRights = 0x0000013B; // create/delete child, self, RP/WP, extended right

    public SecurityDescriptor Descriptor { get; }
    public SecurityDescriptor OriginalDescriptor { get; }
    public SecurityMasks WriteIntent { get; }

    public AclMutationEngine(SecurityDescriptor descriptor)
        : this(descriptor ?? throw new ArgumentNullException(nameof(descriptor)), descriptor, 0) { }

    private AclMutationEngine(SecurityDescriptor descriptor, SecurityDescriptor original, SecurityMasks intent)
        => (Descriptor, OriginalDescriptor, WriteIntent) = (descriptor, original, intent);

    public AclMutationResult Modify(SecurityMasks section, AclModification operation, Ace rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!Enum.IsDefined(operation)) throw new ArgumentOutOfRangeException(nameof(operation));
        var isDacl = ValidateSection(section);
        ValidateRule(rule, isDacl);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (!isDacl && baseline is null
            && operation is AclModification.Remove or AclModification.RemoveSpecific or AclModification.RemoveAll)
            return new(this, true, false); // recorded absent/NULL SACL ModifyAuditRule contract
        var aces = Prepare(section, isDacl, operation is AclModification.Set or AclModification.Reset ? rule.Sid : null);
        var returned = true;
        switch (operation)
        {
            case AclModification.Add:
                Add(aces, rule, isDacl);
                break;
            case AclModification.Set:
            case AclModification.Reset:
                aces.RemoveAll(ace => Explicit(ace) && SameSid(ace, rule)
                    && (operation == AclModification.Reset || SameQualifier(ace, rule)));
                Add(aces, rule, isDacl);
                break;
            case AclModification.Remove:
                if (!Remove(aces, rule)) return new(this, false, false);
                break;
            case AclModification.RemoveSpecific:
                aces.RemoveAll(ace => Explicit(ace) && ace.RawBytes.SequenceEqual(rule.RawBytes));
                break;
            case AclModification.RemoveAll:
                aces.RemoveAll(ace => Explicit(ace) && SameSid(ace, rule) && SameQualifier(ace, rule));
                break;
        }
        return PublishAcl(section, baseline, aces, Descriptor.Control, returned, true,
            rule.ObjectFlags != 0 && operation is AclModification.Add or AclModification.Set or AclModification.Reset);
    }

    public AclMutationResult ModifyAccessRule(AclModification operation, Ace rule)
        => Modify(SecurityMasks.Dacl, operation, rule);

    public AclMutationResult ModifyAuditRule(AclModification operation, Ace rule)
        => Modify(SecurityMasks.Sacl, operation, rule);

    public AclMutationResult RemoveAccess(Sid identity, bool deny)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return ModifyAccessRule(AclModification.RemoveAll, Create((byte)(deny ? 1 : 0), 0, uint.MaxValue, identity));
    }

    public AclMutationResult RemoveAudit(Sid identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return ModifyAuditRule(AclModification.RemoveAll, Create(2, 0xC0, uint.MaxValue, identity));
    }

    public AclMutationResult SetAccessRuleProtection(bool isProtected, bool preserveInheritance)
        => SetProtection(SecurityMasks.Dacl, isProtected, preserveInheritance);

    public AclMutationResult SetAuditRuleProtection(bool isProtected, bool preserveInheritance)
        => SetProtection(SecurityMasks.Sacl, isProtected, preserveInheritance);

    public AclMutationResult Purge(SecurityMasks section, Sid identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var isDacl = ValidateSection(section);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        var aces = Prepare(section, isDacl);
        aces.RemoveAll(ace => Explicit(ace) && identity.Equals(ace.Sid));
        return PublishAcl(section, baseline, aces, Descriptor.Control, true, true);
    }

    public AclMutationResult SetProtection(SecurityMasks section, bool isProtected, bool preserveInheritance)
    {
        var isDacl = ValidateSection(section);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        var aces = Prepare(section, isDacl);
        var bit = isDacl ? 0x1000 : 0x2000;
        var control = (ushort)(isProtected ? Descriptor.Control | bit : Descriptor.Control & ~bit);
        // The detached AD oracle retains INHERITED bits when preserving inheritance;
        // conversion/recalculation at a directory write is outside this internal engine.
        if (isProtected && !preserveInheritance) aces.RemoveAll(ace => !Explicit(ace));
        return PublishAcl(section, baseline, aces, control, true, true);
    }

    public AclMutationResult SetOwner(Sid owner) => SetIdentity(SecurityMasks.Owner, owner);
    public AclMutationResult SetGroup(Sid group) => SetIdentity(SecurityMasks.Group, group);

    private AclMutationResult SetIdentity(SecurityMasks section, Sid identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        RequireRetrieved(section);
        var current = section == SecurityMasks.Owner ? Descriptor.Owner : Descriptor.Group;
        if (identity.Equals(current)) return new(this, true, true);
        var descriptor = DescriptorRewriter.Rewrite(Descriptor, Descriptor.Control,
            new Dictionary<SecurityMasks, byte[]?> { [section] = identity.ToArray() });
        return Publish(descriptor, section, true, true);
    }

    private AclMutationResult PublishAcl(SecurityMasks section, Acl? baseline, List<Ace> aces,
        ushort control, bool returned, bool modified, bool upgradeRevision = false)
    {
        // Removing from an absent SACL does not manufacture an empty section.
        if (section == SecurityMasks.Sacl && baseline is null && aces.Count == 0)
        {
            if (control == Descriptor.Control) return new(this, returned, modified);
            return Publish(DescriptorRewriter.Rewrite(Descriptor, control,
                new Dictionary<SecurityMasks, byte[]?>()), section, returned, modified);
        }
        var bytes = DescriptorRewriter.EncodeAcl(baseline, aces);
        if (upgradeRevision) bytes[0] = Acl.RevisionDS;
        control |= section == SecurityMasks.Dacl ? SecurityDescriptor.DaclPresent : SecurityDescriptor.SaclPresent;
        if (baseline is not null && control == Descriptor.Control && bytes[0] == baseline.AclRevision)
        {
            var old = new byte[baseline.BinaryLength];
            baseline.WriteTo(old);
            if (bytes.AsSpan().SequenceEqual(old)) return new(this, returned, modified);
            // A clean projection is not write intent: no-match/identical operations must
            // not publish incidental IO/NP/order normalization of the raw baseline.
            var clean = Acl.Read(DescriptorRewriter.EncodeAcl(null, baseline.Aces));
            var projected = MicrosoftObservableProjector.NormalizeForEdit(clean, section == SecurityMasks.Dacl);
            if (projected.Aces.Count == aces.Count
                && projected.Aces.Select((ace, index) => ace.RawBytes.SequenceEqual(aces[index].RawBytes)).All(equal => equal))
                return new(this, returned, modified);
        }
        var descriptor = DescriptorRewriter.Rewrite(Descriptor, control,
            new Dictionary<SecurityMasks, byte[]?> { [section] = bytes });
        return Publish(descriptor, section, returned, modified);
    }

    private AclMutationResult Publish(SecurityDescriptor descriptor, SecurityMasks section, bool returned, bool modified)
    {
        if (descriptor.GetBinaryForm().AsSpan().SequenceEqual(Descriptor.GetBinaryForm()))
            return new(this, returned, modified);
        return new(new AclMutationEngine(descriptor, OriginalDescriptor, WriteIntent | section), returned, modified);
    }

    private bool ValidateSection(SecurityMasks section)
    {
        if (section != SecurityMasks.Dacl && section != SecurityMasks.Sacl)
            throw new ArgumentOutOfRangeException(nameof(section));
        RequireRetrieved(section);
        if (Descriptor.HasAclDataWithoutPresentBit(section))
            throw new InvalidOperationException("Cannot edit an ACL with contradictory presence metadata.");
        return section == SecurityMasks.Dacl;
    }

    private void RequireRetrieved(SecurityMasks section)
    {
        if (!Descriptor.IsRetrieved(section)) throw new InvalidOperationException("The section was not retrieved.");
    }

    private List<Ace> Prepare(SecurityMasks section, bool isDacl, Sid? auditReplacementSid = null)
    {
        var acl = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (acl is null)
        {
            if (!isDacl) return new();
            return new() { Create(0, 3, uint.MaxValue, Sid.Parse("S-1-1-0")) };
        }
        if (acl.AclRevision is not (Acl.Revision or Acl.RevisionDS))
            throw new InvalidOperationException("Mutation of this ACL revision has not been validated.");
        var lastGroup = -1;
        foreach (var ace in acl.Aces)
        {
            if (!MicrosoftObservableProjector.IsUnderstoodAce(ace, isDacl))
                throw new InvalidOperationException("An opaque, trailing, wrong-kind or unknown-flags ACE cannot be safely edited.");
            if (MicrosoftObservableProjector.IsInactiveInheritOnly(ace, isDacl)) continue;
            var group = !Explicit(ace) ? 2 : isDacl && IsDeny(ace) ? 0 : 1;
            if (group < lastGroup) throw new InvalidOperationException("The ACL is not in canonical form.");
            lastGroup = group;
        }
        // D13 normalization is explicit here as part of the requested section mutation.
        var cleanHeader = Acl.Read(DescriptorRewriter.EncodeAcl(null, acl.Aces));
        var projected = MicrosoftObservableProjector.NormalizeForEdit(cleanHeader, isDacl).Aces.ToList();
        // Recognized common/object OI flags use the recorded DS scope rules. Scope()
        // retains invalid propagation as a failed operation rather than discarding data;
        // only the reviewed D13 normalization above may remove an inactive ACE.
        if (!isDacl && projected.Count(Explicit) > 1
            && (auditReplacementSid is null || projected.Any(ace => Explicit(ace) && !auditReplacementSid.Equals(ace.Sid))))
            throw new InvalidOperationException("Mutation of multiple explicit SACL entries awaits the I2 ordering decision.");
        return projected;
    }

    private static void ValidateRule(Ace rule, bool isDacl)
    {
        if (!MicrosoftObservableProjector.IsUnderstoodAce(rule, isDacl)
            || !Explicit(rule) || (rule.AceFlags & 0x0F) is not (0 or 2 or 3 or 6 or 10 or 14))
            throw new ArgumentException("The rule is not a supported explicit directory ACE.", nameof(rule));
        if (rule.Kind is AceKind.ObjectAccess or AceKind.ObjectAudit && rule.ObjectFlags == 0)
            throw new ArgumentException("An object rule without GUID flags has no validated Microsoft rule mapping; use the effective common rule shape.", nameof(rule));
        if (rule.AccessMask == 0) throw new ArgumentException("A rule mask must not be zero.", nameof(rule));
        if (!isDacl && (rule.AceFlags & 0xC0) == 0)
            throw new ArgumentException("An audit rule requires success or failure.", nameof(rule));
    }

    private static void Add(List<Ace> aces, Ace rule, bool isDacl)
    {
        for (var i = 0; i < aces.Count; i++)
        {
            var ace = aces[i];
            if (!Explicit(ace) || !SameShape(ace, rule)) continue;
            if (ace.AceFlags == rule.AceFlags)
            {
                aces[i] = With(ace, ace.AccessMask | rule.AccessMask, ace.AceFlags);
                return;
            }
            if (ace.AccessMask != rule.AccessMask) continue;
            if ((ace.AceFlags & 0x0F) == (rule.AceFlags & 0x0F))
            {
                aces[i] = With(ace, ace.AccessMask, (byte)(ace.AceFlags | rule.AceFlags));
                return;
            }
            if ((ace.AceFlags & 0xC0) == (rule.AceFlags & 0xC0)
                && TryFlags(Scope(ace) | Scope(rule), out var flags))
            {
                aces[i] = With(ace, ace.AccessMask, (byte)((ace.AceFlags & 0xC0) | flags));
                return;
            }
        }
        // Insert without disturbing the relative order of any existing ACEs.
        var rank = Rank(rule, isDacl);
        var at = aces.FindIndex(ace => Rank(ace, isDacl) > rank
            || (Rank(ace, isDacl) == rank && CompareSid(ace.Sid!, rule.Sid!) > 0));
        aces.Insert(at < 0 ? aces.Count : at, rule);
    }

    private static bool Remove(List<Ace> aces, Ace rule)
    {
        var result = new List<Ace>();
        foreach (var ace in aces)
        {
            if (!Explicit(ace) || !SameSid(ace, rule) || !SameQualifier(ace, rule)
                || (ace.AccessMask & rule.AccessMask) == 0)
            {
                result.Add(ace);
                continue;
            }
            var removeFlags = rule.AceFlags;
            // DS scope-disjointness uses CI/IO, not OI. In particular OI|IO without
            // CI is retained raw and is an invalid propagation matrix, not an empty one.
            if (((ace.AceFlags & 2) == 0 && (removeFlags & 10) == 10)
                || ((removeFlags & 2) == 0 && (ace.AceFlags & 10) == 10))
            {
                result.Add(ace);
                continue;
            }
            // ObjectType qualifies only DS object-specific bits. Global rights still
            // match across GUIDs (recorded mixed RP|ListChildren subtraction).
            var removeMask = rule.AccessMask;
            var objectTypesConflict = rule.ObjectType.HasValue && !ace.ObjectType.HasValue
                && (ace.AccessMask & removeMask & ObjectQualifiedRights) != 0;
            if (!objectTypesConflict && rule.ObjectType.HasValue && rule.ObjectType != ace.ObjectType)
                removeMask &= ~ObjectQualifiedRights;
            if ((ace.AccessMask & removeMask) == 0)
            {
                result.Add(ace);
                continue;
            }
            if ((ace.AceFlags & rule.AceFlags & 2) != 0 && rule.InheritedObjectType.HasValue)
            {
                if (!ace.InheritedObjectType.HasValue) return false;
                if (rule.InheritedObjectType != ace.InheritedObjectType)
                {
                    // Different child types share no propagation. A descendants-only
                    // request cannot remove self; an all-scope request can remove self
                    // while retaining the existing GUID-qualified descendants.
                    if ((rule.AceFlags & 8) != 0 || (ace.AceFlags & 8) != 0)
                    {
                        result.Add(ace);
                        continue;
                    }
                    removeFlags &= 0xf0;
                }
            }
            // A missing object GUID is a conflict only after inherited-GUID filtering
            // establishes shared scope; recorded descendant no-ops take precedence.
            if (objectTypesConflict) return false;
            var oldAudit = ace.AceFlags & 0xC0;
            var removeAudit = rule.AceFlags & 0xC0;
            if (oldAudit != 0 && (oldAudit & removeAudit) == 0)
            {
                result.Add(ace);
                continue;
            }
            var oldScope = Scope(ace);
            var removeScope = Scope(removeFlags);
            if (oldScope < 0 || removeScope < 0) return false;
            var remainingScope = oldScope & ~removeScope;
            if (!TryFlags(remainingScope, out var remainingFlags)) return false;
            var overlapMask = ace.AccessMask & removeMask;
            var remainingMask = ace.AccessMask & ~removeMask;
            if (remainingMask != 0) result.Add(Split(ace, remainingMask, ace.AceFlags));
            if (oldAudit != 0)
            {
                var remainingAudit = oldAudit & ~removeAudit;
                if (remainingAudit != 0)
                    result.Add(Split(ace, overlapMask, (byte)((ace.AceFlags & 0x0F) | remainingAudit)));
            }
            if (remainingScope != 0)
                result.Add(Split(ace, overlapMask, (byte)(remainingFlags | (oldAudit & removeAudit))));
        }
        aces.Clear();
        aces.AddRange(result);
        return true;
    }

    private static bool Explicit(Ace ace) => (ace.AceFlags & 0x10) == 0;
    private static bool IsDeny(Ace ace) => ace.AceType is 1 or 6;
    private static bool SameSid(Ace a, Ace b) => a.Sid!.Equals(b.Sid);
    private static bool SameQualifier(Ace a, Ace b) => IsDeny(a) == IsDeny(b);
    private static bool SameShape(Ace a, Ace b) => a.AceType == b.AceType && SameSid(a, b)
        && a.ObjectFlags == b.ObjectFlags && a.ObjectType == b.ObjectType && a.InheritedObjectType == b.InheritedObjectType;
    private static int Rank(Ace ace, bool isDacl) => !Explicit(ace) ? 4
        : (isDacl && !IsDeny(ace) ? 2 : 0) + (ace.Kind is AceKind.ObjectAccess or AceKind.ObjectAudit ? 1 : 0);
    private static int CompareSid(Sid a, Sid b)
    {
        var result = a.IdentifierAuthority.CompareTo(b.IdentifierAuthority);
        if (result != 0) return result;
        result = a.SubAuthorityCount.CompareTo(b.SubAuthorityCount);
        if (result != 0) return result;
        for (var i = 0; i < a.SubAuthorityCount; i++)
        {
            result = a.GetSubAuthority(i).CompareTo(b.GetSubAuthority(i));
            if (result != 0) return result;
        }
        return a.SubAuthorityCount.CompareTo(b.SubAuthorityCount);
    }

    // Directory-service propagation: self, immediate containers, deeper containers.
    private static int Scope(Ace ace) => Scope(ace.AceFlags);
    private static int Scope(byte flags)
    {
        // In DS ACL propagation OI contributes no scope. NP/IO without CI is invalid
        // even when OI kept the ACE alive during import; removal must fail atomically.
        if ((flags & 2) == 0 && (flags & 12) != 0) return -1;
        var self = (flags & 8) == 0 ? 1 : 0;
        return self | ((flags & 2) == 0 ? 0 : (flags & 4) != 0 ? 2 : 6);
    }
    private static bool TryFlags(int scope, out byte flags)
    {
        flags = scope switch { 0 or 1 => 0, 2 => 14, 3 => 6, 6 => 10, 7 => 2, _ => 0 };
        return scope is 0 or 1 or 2 or 3 or 6 or 7;
    }
    private static Ace Split(Ace source, uint mask, byte flags)
    {
        if (source.Kind is not (AceKind.ObjectAccess or AceKind.ObjectAudit))
            return With(source, mask, flags);
        // Microsoft keeps the object ACE family, but removes GUID fields no longer
        // applicable to this split's mask/propagation. Never reuse stale GUID bytes.
        var objectFlags = source.ObjectFlags;
        if ((mask & ObjectQualifiedRights) == 0) objectFlags &= ~Ace.ObjectTypePresent;
        if ((flags & 2) == 0) objectFlags &= ~Ace.InheritedObjectTypePresent;
        var length = 12 + source.Sid!.BinaryLength
            + ((objectFlags & 1) != 0 ? 16 : 0) + ((objectFlags & 2) != 0 ? 16 : 0);
        var bytes = new byte[length];
        bytes[0] = source.AceType;
        bytes[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), (ushort)length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), mask);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), objectFlags);
        var cursor = 12;
        if ((objectFlags & 1) != 0) { source.ObjectType!.Value.TryWriteBytes(bytes.AsSpan(cursor)); cursor += 16; }
        if ((objectFlags & 2) != 0) { source.InheritedObjectType!.Value.TryWriteBytes(bytes.AsSpan(cursor)); cursor += 16; }
        source.Sid.WriteTo(bytes.AsSpan(cursor));
        return Ace.Read(bytes);
    }

    private static Ace With(Ace source, uint mask, byte flags)
    {
        if (source.TrailingLength != 0 || source.Kind == AceKind.Opaque)
            throw new InvalidOperationException("Cannot reconstruct an ACE with unexplained data.");
        var bytes = source.RawBytes.ToArray();
        bytes[1] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), mask);
        return Ace.Read(bytes);
    }
    private static Ace Create(byte type, byte flags, uint mask, Sid sid)
    {
        var bytes = new byte[8 + sid.BinaryLength];
        bytes[0] = type;
        bytes[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), (ushort)bytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), mask);
        sid.WriteTo(bytes.AsSpan(8));
        return Ace.Read(bytes);
    }
}
