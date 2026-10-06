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
        var aces = Prepare(section, isDacl);
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
        return PublishAcl(section, baseline, aces, Descriptor.Control, returned, true);
    }

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
        if (isProtected)
        {
            if (!preserveInheritance) aces.RemoveAll(ace => !Explicit(ace));
            else
            {
                // Converting inherited ACEs can require movement. Only understood ACEs reach here.
                aces = aces.Select(ace => With(ace, ace.AccessMask, (byte)(ace.AceFlags & ~0x10))).ToList();
                if (!isDacl && aces.Count > 1)
                    throw new InvalidOperationException("SACL reordering after inheritance conversion is deferred.");
                aces = aces.OrderBy(ace => Rank(ace, isDacl)).ToList();
            }
        }
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
        ushort control, bool returned, bool modified)
    {
        // Removing from an absent SACL does not manufacture an empty section.
        if (section == SecurityMasks.Sacl && baseline is null && aces.Count == 0)
        {
            if (control == Descriptor.Control) return new(this, returned, modified);
            return Publish(DescriptorRewriter.Rewrite(Descriptor, control,
                new Dictionary<SecurityMasks, byte[]?>()), section, returned, modified);
        }
        var bytes = DescriptorRewriter.EncodeAcl(baseline, aces);
        control |= section == SecurityMasks.Dacl ? SecurityDescriptor.DaclPresent : SecurityDescriptor.SaclPresent;
        if (baseline is not null && control == Descriptor.Control)
        {
            var old = new byte[baseline.BinaryLength];
            baseline.WriteTo(old);
            if (bytes.AsSpan().SequenceEqual(old)) return new(this, returned, modified);
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

    private List<Ace> Prepare(SecurityMasks section, bool isDacl)
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
        var projected = MicrosoftObservableProjector.ProjectAcl(cleanHeader, isDacl).Aces.ToList();
        if (projected.Any(ace => (ace.AceFlags & 0x0F) is not (0 or 2 or 3 or 6 or 10 or 14)))
            throw new InvalidOperationException("This propagation flag combination is outside the recorded directory semantics.");
        if (!isDacl && projected.Count(Explicit) > 1)
            throw new InvalidOperationException("Mutation of multiple explicit SACL entries awaits the I2 ordering decision.");
        return projected;
    }

    private static void ValidateRule(Ace rule, bool isDacl)
    {
        if (!MicrosoftObservableProjector.IsUnderstoodAce(rule, isDacl)
            || !Explicit(rule) || (rule.AceFlags & 0x0F) is not (0 or 2 or 3 or 6 or 10 or 14))
            throw new ArgumentException("The rule is not a supported explicit directory ACE.", nameof(rule));
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
            // Narrowing an unqualified right into one object type is not representable.
            if (rule.ObjectType.HasValue && !ace.ObjectType.HasValue) return false;
            if (rule.ObjectType.HasValue && rule.ObjectType != ace.ObjectType)
            {
                result.Add(ace);
                continue;
            }
            if (rule.InheritedObjectType.HasValue && !ace.InheritedObjectType.HasValue) return false;
            if (rule.InheritedObjectType.HasValue && rule.InheritedObjectType != ace.InheritedObjectType)
            {
                result.Add(ace);
                continue;
            }
            var oldScope = Scope(ace);
            var removeScope = Scope(rule);
            var oldAudit = ace.AceFlags & 0xC0;
            var removeAudit = rule.AceFlags & 0xC0;
            if ((oldScope & removeScope) == 0 || (oldAudit != 0 && (oldAudit & removeAudit) == 0))
            {
                result.Add(ace);
                continue;
            }
            var remainingScope = oldScope & ~removeScope;
            if (!TryFlags(remainingScope, out var remainingFlags)) return false;
            var overlapMask = ace.AccessMask & rule.AccessMask;
            var remainingMask = ace.AccessMask & ~rule.AccessMask;
            if (remainingMask != 0) result.Add(With(ace, remainingMask, ace.AceFlags));
            if (oldAudit != 0)
            {
                var remainingAudit = oldAudit & ~removeAudit;
                if (remainingAudit != 0)
                    result.Add(With(ace, overlapMask, (byte)((ace.AceFlags & 0x0F) | remainingAudit)));
            }
            if (remainingScope != 0)
                result.Add(With(ace, overlapMask, (byte)(remainingFlags | (oldAudit & removeAudit))));
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
        for (var i = 0; i < Math.Min(a.SubAuthorityCount, b.SubAuthorityCount); i++)
        {
            result = a.GetSubAuthority(i).CompareTo(b.GetSubAuthority(i));
            if (result != 0) return result;
        }
        return a.SubAuthorityCount.CompareTo(b.SubAuthorityCount);
    }

    // Directory-service propagation: self, immediate containers, deeper containers.
    private static int Scope(Ace ace)
    {
        var flags = ace.AceFlags;
        var self = (flags & 8) == 0 ? 1 : 0;
        return self | ((flags & 2) == 0 ? 0 : (flags & 4) != 0 ? 2 : 6);
    }
    private static bool TryFlags(int scope, out byte flags)
    {
        flags = scope switch { 0 or 1 => 0, 2 => 14, 3 => 6, 6 => 10, 7 => 2, _ => 0 };
        return scope is 0 or 1 or 2 or 3 or 6 or 7;
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
