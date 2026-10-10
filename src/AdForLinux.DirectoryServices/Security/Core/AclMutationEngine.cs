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
    private readonly ProjectedState? _projectedDacl;
    private readonly ProjectedState? _projectedSacl;

    public AclMutationEngine(SecurityDescriptor descriptor)
        : this(descriptor ?? throw new ArgumentNullException(nameof(descriptor)), descriptor, 0) { }

    private AclMutationEngine(SecurityDescriptor descriptor, SecurityDescriptor original, SecurityMasks intent,
        ProjectedState? projectedDacl = null, ProjectedState? projectedSacl = null)
        => (Descriptor, OriginalDescriptor, WriteIntent, _projectedDacl, _projectedSacl)
            = (descriptor, original, intent, projectedDacl, projectedSacl);

    public AclMutationResult Modify(SecurityMasks section, AclModification operation, Ace rule)
    {
        RequireRawAcl(section);
        ArgumentNullException.ThrowIfNull(rule);
        if (!Enum.IsDefined(operation)) throw new ArgumentOutOfRangeException(nameof(operation));
        var isDacl = ValidateSection(section);
        ValidateRule(rule, isDacl);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (!isDacl && baseline is null
            && operation is AclModification.Remove or AclModification.RemoveSpecific or AclModification.RemoveAll)
            return new(this, true, false); // recorded absent/NULL SACL ModifyAuditRule contract
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
        return PublishAcl(section, baseline, aces, Descriptor.Control, returned, true,
            rule.ObjectFlags != 0 && operation is AclModification.Add or AclModification.Set or AclModification.Reset);
    }

    /// <summary>
    /// Returns the retained Microsoft-style live view, without re-importing its raw
    /// contributors. A new engine constructed from Descriptor explicitly starts a new import.
    /// </summary>
    public SecurityDescriptor GetObservableDescriptor()
    {
        var replacements = new Dictionary<SecurityMasks, byte[]?>();
        foreach (var section in new[] { SecurityMasks.Dacl, SecurityMasks.Sacl })
        {
            var acl = GetObservableAcl(section);
            if (acl is not null) replacements.Add(section, DescriptorRewriter.EncodeAcl(acl, acl.Aces));
        }
        var control = Descriptor.DaclState == AclState.Null
            ? (ushort)(Descriptor.Control & ~SecurityDescriptor.DaclPresent) : Descriptor.Control;
        return DescriptorRewriter.RepackObservable(Descriptor, control, replacements);
    }

    // Section-local reads do not interpret an unrelated opaque ACL. The full descriptor
    // getter explicitly requests both projections and retains their strict validation.
    public Acl? GetObservableAcl(SecurityMasks section)
    {
        var isDacl = ValidateSection(section);
        var acl = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (acl is null) return null;
        if (acl.AclRevision is not (Acl.Revision or Acl.RevisionDS)
            || acl.Sbz1 != 0 || acl.Sbz2 != 0 || !acl.Trailing.IsEmpty)
            throw new InvalidOperationException("Microsoft projection of ACL revision, reserved or trailing data is not validated.");
        var state = RetainedState(section);
        if (state is null) return MicrosoftObservableProjector.ProjectAcl(acl, isDacl);
        ValidateProvenance(acl, state);
        var bytes = DescriptorRewriter.EncodeAcl(null, state.Groups.Select(group => group.View).ToArray());
        bytes[0] = acl.AclRevision;
        return Acl.Read(bytes);
    }

    /// <summary>
    /// Edits retained live entries and reconciles their original contributor occurrences.
    /// Unrelated groups remain intact even when a fresh import would regroup raw bytes.
    /// </summary>
    public AclMutationResult ModifyProjected(SecurityMasks section, AclModification operation, Ace rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!Enum.IsDefined(operation)) throw new ArgumentOutOfRangeException(nameof(operation));
        var isDacl = ValidateSection(section);
        ValidateRule(rule, isDacl);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (baseline is null) return Modify(section, operation, rule);
        var groups = ProjectedGroups(section, isDacl);
        var before = groups.Select(group => group.View).ToList();
        var expected = before.ToList();
        if (operation is AclModification.Set or AclModification.Reset or AclModification.RemoveAll)
            expected.RemoveAll(ace => Explicit(ace) && SameSid(ace, rule)
                && (operation == AclModification.Reset || SameQualifier(ace, rule)));
        if (operation is AclModification.Add or AclModification.Set or AclModification.Reset) Add(expected, rule, isDacl);
        else if (operation == AclModification.Remove && !Remove(expected, rule)) return new(this, false, false);
        else if (operation == AclModification.RemoveSpecific)
            expected.RemoveAll(ace => Explicit(ace) && ace.RawBytes.SequenceEqual(rule.RawBytes));
        var upgrade = rule.ObjectFlags != 0 && operation is AclModification.Add or AclModification.Set or AclModification.Reset;
        if (SameEntries(before, expected))
        {
            if (upgrade && baseline.AclRevision != Acl.RevisionDS)
                return PublishProjected(section, groups, Descriptor.Control, true);
            return new(this, true, true);
        }

        var updated = new List<ProjectedGroup>();
        var added = false;
        foreach (var group in groups)
        {
            if (operation is AclModification.Set or AclModification.Reset or AclModification.RemoveAll
                && Explicit(group.View) && SameSid(group.View, rule)
                && (operation == AclModification.Reset || SameQualifier(group.View, rule))) continue;
            var changed = new List<Ace> { group.View };
            if (operation is AclModification.Add or AclModification.Set or AclModification.Reset)
            {
                if (!added && TryMerge(group.View, rule, out var merged))
                {
                    changed[0] = merged;
                    added = true;
                }
            }
            else if (operation == AclModification.Remove)
            {
                if (!Remove(changed, rule)) return new(this, false, false);
            }
            else if (operation == AclModification.RemoveSpecific
                && Explicit(group.View) && group.View.RawBytes.SequenceEqual(rule.RawBytes)) changed.Clear();

            if (SameEntries(new[] { group.View }, changed)) updated.Add(group);
            else
            {
                var distributed = group.Contributors.ToList();
                var valid = true;
                if (operation is AclModification.Add or AclModification.Set or AclModification.Reset) Add(distributed, rule, isDacl);
                else if (operation == AclModification.Remove) valid = Remove(distributed, rule);
                else distributed.Clear();
                AclCanonicalizer.Sort(distributed, isDacl);
                var reconciled = ImportGroups(distributed);
                updated.AddRange(valid && SameEntries(reconciled.Select(value => value.View).ToArray(), changed)
                    ? reconciled : changed.Select(ace => new ProjectedGroup(ace, new[] { ace })));
            }
        }
        if (operation is AclModification.Add or AclModification.Set or AclModification.Reset && !added)
        {
            updated.Add(new(rule, new[] { rule }));
            AclCanonicalizer.Sort(updated, group => group.View, isDacl);
        }
        if (!SameEntries(updated.Select(group => group.View).ToArray(), expected))
            throw new InvalidOperationException("The live operation could not be reconciled with contributor occurrences; no state was published.");
        return PublishProjected(section, updated, Descriptor.Control, upgrade);
    }

    public AclMutationResult PurgeProjected(SecurityMasks section, Sid identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var isDacl = ValidateSection(section);
        if ((isDacl ? Descriptor.Dacl : Descriptor.Sacl) is null) return Purge(section, identity);
        var groups = ProjectedGroups(section, isDacl);
        if (groups.RemoveAll(group => Explicit(group.View) && identity.Equals(group.View.Sid)) == 0)
            return new(this, true, true);
        return PublishProjected(section, groups, Descriptor.Control);
    }

    public AclMutationResult SetProtectionProjected(SecurityMasks section, bool isProtected, bool preserveInheritance)
    {
        var isDacl = ValidateSection(section);
        if ((isDacl ? Descriptor.Dacl : Descriptor.Sacl) is null) return SetProtection(section, isProtected, preserveInheritance);
        var groups = ProjectedGroups(section, isDacl);
        var bit = isDacl ? 0x1000 : 0x2000;
        var control = (ushort)(isProtected ? Descriptor.Control | bit : Descriptor.Control & ~bit);
        var removed = isProtected && !preserveInheritance ? groups.RemoveAll(group => !Explicit(group.View)) : 0;
        if (removed == 0 && control == Descriptor.Control) return new(this, true, true);
        return PublishProjected(section, groups, control);
    }

    private sealed record ProjectedGroup(Ace View, Ace[] Contributors);
    private sealed record ProjectedState(ProjectedGroup[] Groups, byte[] RawAcl);

    // Detached edit-back is a value diff, not an operation journal. Only unique,
    // single-contributor mask/deletion edits and non-merging explicit insertions have
    // a proven interpretation. Every operation below uses the original occurrence map;
    // intermediate candidates never become a replacement baseline.
    internal AclMutationEngine ReconcileInteropEdits(SecurityMasks section, byte[] baseline, byte[] edited)
    {
        var isDacl = ValidateSection(section);
        var raw = (isDacl ? Descriptor.Dacl : Descriptor.Sacl)
            ?? throw new NotSupportedException("ACL state transitions require explicit operation provenance.");
        var current = GetObservableAcl(section)!;
        if (!DescriptorRewriter.EncodeAcl(current, current.Aces).AsSpan().SequenceEqual(baseline))
            throw new NotSupportedException("Fresh-import regrouping cannot be mapped back to retained live occurrences.");
        var before = Acl.Read(baseline); var after = Acl.Read(edited);
        // Only size/count can change. Revision, reserved fields and the present/NULL
        // state stay unchanged; each edit is proven against original contributors.
        if (!baseline.AsSpan(0, 2).SequenceEqual(edited.AsSpan(0, 2))
            || !baseline.AsSpan(6, 2).SequenceEqual(edited.AsSpan(6, 2))
            || !after.Trailing.IsEmpty)
            throw new NotSupportedException("ACL revision/reserved fields and trailing data cannot be reconciled.");

        var groups = new List<(Ace View, int[] RawIndices)>();
        var retained = RetainedState(section);
        if (retained is not null)
        {
            ValidateProvenance(raw, retained);
            var cursor = 0;
            foreach (var group in retained.Groups)
            {
                groups.Add((group.View, Enumerable.Range(cursor, group.Contributors.Length).ToArray()));
                cursor += group.Contributors.Length;
            }
        }
        else
        {
            // Validate the whole ACL first. Individual normalization below retains
            // original occurrence indices, including originals omitted from the view.
            _ = MicrosoftObservableProjector.NormalizeForEdit(raw, isDacl);
            for (var i = 0; i < raw.Aces.Count; i++)
            {
                var singleton = Acl.Read(DescriptorRewriter.EncodeAcl(raw, new[] { raw.Aces[i] }));
                var normalized = MicrosoftObservableProjector.NormalizeForEdit(singleton, isDacl);
                if (normalized.Aces.Count != 0) groups.Add((normalized.Aces[0], new[] { i }));
            }
            AclCanonicalizer.Sort(groups, group => group.View, isDacl);
            for (var i = 0; i < groups.Count - 1; i++)
            {
                if (!TryMerge(groups[i].View, groups[i + 1].View, out var merged)) continue;
                groups[i] = (merged, groups[i].RawIndices.Concat(groups[i + 1].RawIndices).ToArray());
                groups.RemoveAt(i + 1);
            }
        }
        if (!SameEntries(groups.Select(g => g.View).ToArray(), before.Aces))
            throw new NotSupportedException("The exported occurrences do not have a proven contributor mapping.");
        // Read projection intentionally preserves noncanonical input. Matching its
        // bytes cannot prove that a canonical CommonAcl can install the candidate.
        if (!MicrosoftObservableProjector.HasCanonicalQualifierOrder(before.Aces, isDacl)
            || !MicrosoftObservableProjector.HasCanonicalQualifierOrder(after.Aces, isDacl))
            throw new NotSupportedException("Edit-back requires canonical explicit/inherited and deny/allow ordering.");
        var replacements = raw.Aces.ToArray();
        var removed = new HashSet<int>();
        var touched = new List<Ace>();
        var candidateGroups = new List<(Ace View, int[] RawIndices)>();
        var added = new List<Ace>();
        var oldIndex = 0;
        foreach (var ace in after.Aces)
        {
            // Match only original non-mask fields, never the output of a previous
            // edit. Unchanged duplicate shapes can survive in their original order;
            // changing or removing one requires unique original identity below.
            var match = groups.FindIndex(oldIndex, group => SameExceptMask(group.View, ace));
            if (match < 0)
            {
                if (groups.Any(group => SameExceptMask(group.View, ace)))
                    throw new NotSupportedException("An original occurrence was duplicated or reordered.");
                if (!Explicit(ace) || !MicrosoftObservableProjector.IsUnderstoodAce(ace, isDacl)
                    || ace.AccessMask == 0 || (!isDacl && (ace.AceFlags & 0xC0) == 0))
                    throw new NotSupportedException("Insertion requires a new understood explicit nonzero ACE.");
                var singleton = Acl.Read(DescriptorRewriter.EncodeAcl(raw, new[] { ace }));
                var normalized = MicrosoftObservableProjector.NormalizeForEdit(singleton, isDacl);
                if (normalized.Aces.Count != 1 || !normalized.Aces[0].RawBytes.SequenceEqual(ace.RawBytes))
                    throw new NotSupportedException("A new ACE cannot require projection normalization.");
                added.Add(ace); candidateGroups.Add((ace, Array.Empty<int>()));
                continue;
            }
            while (oldIndex < match) DeleteOriginal(oldIndex++);
            var original = groups[oldIndex++];
            if (!original.View.RawBytes.SequenceEqual(ace.RawBytes))
            {
                RequireUnique(original);
                if (!MicrosoftObservableProjector.IsUnderstoodAce(ace, isDacl) || ace.AccessMask == 0)
                    throw new NotSupportedException("The edited ACE is not a supported nonzero mask change.");
                var index = original.RawIndices[0];
                var bytes = replacements[index].RawBytes.ToArray();
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), ace.AccessMask);
                replacements[index] = Ace.Read(bytes); touched.Add(original.View);
            }
            candidateGroups.Add((ace, original.RawIndices));
        }
        while (oldIndex < groups.Count) DeleteOriginal(oldIndex++);

        for (var i = 0; i < added.Count; i++)
        {
            var ace = added[i];
            // A same-identity insertion combined with removal/mask change could be
            // a scope/qualifier replacement or split. Do not infer that intent.
            if (touched.Any(original => original.Sid!.Equals(ace.Sid)))
                throw new NotSupportedException("Insertion overlaps a changed identity; replacement or split intent is ambiguous.");
            // Object/scope absorption is asymmetric. Check both directions against
            // original raw/live data AND final survivors, without cascading remaps.
            var others = groups.Select(group => group.View).Concat(raw.Aces)
                .Concat(candidateGroups.Where(group => group.RawIndices.Length != 0).Select(group => group.View))
                .Concat(replacements.Where((_, index) => !removed.Contains(index))).Concat(added.Take(i));
            foreach (var other in others)
                if (SameExceptMask(other, ace) || TryMerge(other, ace, out _) || TryMerge(ace, other, out _))
                    throw new NotSupportedException("Insertion cannot merge with or ambiguously duplicate another occurrence.");
        }

        // Anchor new ACEs before the next surviving ORIGINAL contributor, or at
        // the raw end. Deletions do not renumber anchors; mask edits replace bytes
        // at their original indices. Hidden/unrelated originals never move.
        var placed = new List<Ace>(); var rawCursor = 0;
        for (var i = 0; i < candidateGroups.Count; i++)
        {
            if (candidateGroups[i].RawIndices.Length != 0) continue;
            var following = candidateGroups.Skip(i + 1).FirstOrDefault(group => group.RawIndices.Length != 0);
            var anchor = following.RawIndices is null ? raw.Aces.Count : following.RawIndices.Min();
            if (anchor < rawCursor)
                throw new NotSupportedException("Insertion anchors would move existing raw contributors.");
            CopyThrough(anchor); placed.Add(candidateGroups[i].View);
        }
        CopyThrough(raw.Aces.Count);
        var encoded = DescriptorRewriter.EncodeAcl(raw, placed);
        var descriptor = DescriptorRewriter.Rewrite(Descriptor, Descriptor.Control,
            new Dictionary<SecurityMasks, byte[]?> { [section] = encoded });
        ProjectedState? nextState = retained is null ? null : new(candidateGroups.Select(group =>
            new ProjectedGroup(group.View, group.RawIndices.Length == 0 ? new[] { group.View }
                : group.RawIndices.Select(index => replacements[index]).ToArray())).ToArray(), encoded);
        var next = new AclMutationEngine(descriptor, OriginalDescriptor, WriteIntent | section,
            isDacl ? nextState : _projectedDacl, isDacl ? _projectedSacl : nextState);
        var result = next.GetObservableAcl(section)!;
        if (!DescriptorRewriter.EncodeAcl(result, result.Aces).AsSpan().SequenceEqual(edited))
            throw new NotSupportedException("The compound raw edit does not reproduce the target projection exactly.");
        return next;

        void RequireUnique((Ace View, int[] RawIndices) original)
        {
            if (!Explicit(original.View) || original.RawIndices.Length != 1
                || groups.Count(group => SameExceptMask(group.View, original.View)) != 1)
                throw new NotSupportedException("Ambiguous, merged or inherited ACE edits cannot be reconciled.");
        }
        void DeleteOriginal(int index)
        {
            var original = groups[index]; RequireUnique(original);
            removed.Add(original.RawIndices[0]); touched.Add(original.View);
        }
        void CopyThrough(int anchor)
        {
            while (rawCursor < anchor)
            {
                if (!removed.Contains(rawCursor)) placed.Add(replacements[rawCursor]);
                rawCursor++;
            }
        }

        static bool SameExceptMask(Ace left, Ace right) => left.Size == right.Size
            && left.RawBytes[..4].SequenceEqual(right.RawBytes[..4])
            && left.RawBytes[8..].SequenceEqual(right.RawBytes[8..]);
    }

    private ProjectedState? RetainedState(SecurityMasks section)
        => section == SecurityMasks.Dacl ? _projectedDacl : _projectedSacl;

    private List<ProjectedGroup> ProjectedGroups(SecurityMasks section, bool isDacl)
    {
        var retained = RetainedState(section);
        if (retained is null) return ImportGroups(Prepare(section, isDacl));
        ValidateProvenance((isDacl ? Descriptor.Dacl : Descriptor.Sacl)!, retained);
        return retained.Groups.ToList();
    }

    private static List<ProjectedGroup> ImportGroups(IReadOnlyList<Ace> aces)
    {
        var groups = aces.Select(ace => new ProjectedGroup(ace, new[] { ace })).ToList();
        for (var i = 0; i < groups.Count - 1; i++)
        {
            if (!TryMerge(groups[i].View, groups[i + 1].View, out var merged)) continue;
            groups[i] = new(merged, groups[i].Contributors.Concat(groups[i + 1].Contributors).ToArray());
            groups.RemoveAt(i + 1);
        }
        return groups;
    }

    private static void ValidateProvenance(Acl acl, ProjectedState state)
    {
        var bytes = DescriptorRewriter.EncodeAcl(acl, acl.Aces);
        if (!bytes.AsSpan().SequenceEqual(state.RawAcl)
            || !SameEntries(state.Groups.SelectMany(group => group.Contributors).ToArray(), acl.Aces))
            throw new InvalidOperationException("The retained contributor provenance does not match the raw ACL; no state was published.");
    }

    private AclMutationResult PublishProjected(SecurityMasks section, List<ProjectedGroup> groups,
        ushort control, bool upgradeRevision = false)
    {
        var baseline = section == SecurityMasks.Dacl ? Descriptor.Dacl : Descriptor.Sacl;
        var raw = groups.SelectMany(group => group.Contributors).ToList();
        // Validate both representations before publishing either. Global re-import of
        // raw is deliberately absent: regrouping is an explicit new-import boundary.
        _ = DescriptorRewriter.EncodeAcl(null, groups.Select(group => group.View).ToArray());
        var result = PublishAcl(section, baseline, raw, control, true, true, upgradeRevision);
        var acl = (section == SecurityMasks.Dacl ? result.Engine.Descriptor.Dacl : result.Engine.Descriptor.Sacl)!;
        var state = new ProjectedState(groups.ToArray(), DescriptorRewriter.EncodeAcl(acl, acl.Aces));
        ValidateProvenance(acl, state);
        var engine = result.Engine;
        return new(new AclMutationEngine(engine.Descriptor, engine.OriginalDescriptor, engine.WriteIntent,
            section == SecurityMasks.Dacl ? state : engine._projectedDacl,
            section == SecurityMasks.Sacl ? state : engine._projectedSacl), true, true);
    }

    private void RequireRawAcl(SecurityMasks section)
    {
        if (RetainedState(section) is not null)
            throw new InvalidOperationException("This ACL has retained projected state. Use projected operations or explicitly construct a new engine to re-import; raw mutation cannot discard contributor provenance.");
    }

    private static bool SameEntries(IReadOnlyList<Ace> left, IReadOnlyList<Ace> right)
        => left.Count == right.Count && left.Select((ace, index) => ace.RawBytes.SequenceEqual(right[index].RawBytes)).All(equal => equal);

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
        RequireRawAcl(section);
        ArgumentNullException.ThrowIfNull(identity);
        var isDacl = ValidateSection(section);
        var baseline = isDacl ? Descriptor.Dacl : Descriptor.Sacl;
        var aces = Prepare(section, isDacl);
        aces.RemoveAll(ace => Explicit(ace) && identity.Equals(ace.Sid));
        return PublishAcl(section, baseline, aces, Descriptor.Control, true, true);
    }

    public AclMutationResult SetProtection(SecurityMasks section, bool isProtected, bool preserveInheritance)
    {
        RequireRawAcl(section);
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

    // Explicit facade section assignment is distinct from projected rule editing.
    // Retain provenance for every untouched ACL and apply the same layout safeguards.
    internal AclMutationEngine ReplaceSections(IReadOnlyDictionary<SecurityMasks, byte[]?> replacements,
        ushort controlMask, ushort control)
    {
        var changed = (SecurityMasks)0;
        foreach (var (section, bytes) in replacements)
        {
            RequireRetrieved(section);
            if (section is SecurityMasks.Dacl or SecurityMasks.Sacl)
            {
                if (Descriptor.HasAclDataWithoutPresentBit(section))
                    throw new InvalidOperationException("Section replacement cannot discard ACL storage hidden by an absent present bit.");
                var original = section == SecurityMasks.Dacl ? Descriptor.Dacl : Descriptor.Sacl;
                if (original is not null)
                {
                    var old = new byte[original.BinaryLength]; original.WriteTo(old);
                    if (bytes is not null && old.AsSpan().SequenceEqual(bytes)) continue;
                    if (original.AclRevision is not (Acl.Revision or Acl.RevisionDS)
                        || !original.Trailing.IsEmpty || original.Sbz1 != 0 || original.Sbz2 != 0
                        || original.Aces.Any(a => !MicrosoftObservableProjector.IsUnderstoodAce(a, section == SecurityMasks.Dacl)))
                        throw new InvalidOperationException("Section replacement would discard unreviewed ACL data.");
                }
            }
            else
            {
                var original = section == SecurityMasks.Owner ? Descriptor.Owner : Descriptor.Group;
                if (original is null ? bytes is null : bytes is not null && original.ToArray().AsSpan().SequenceEqual(bytes)) continue;
            }
            changed |= section;
        }
        var replaced = changed;
        var flags = (ushort)((Descriptor.Control & ~controlMask) | (control & controlMask));
        if (((flags ^ Descriptor.Control) & 0x1504) != 0) { RequireRetrieved(SecurityMasks.Dacl); changed |= SecurityMasks.Dacl; }
        if (((flags ^ Descriptor.Control) & 0x2A10) != 0) { RequireRetrieved(SecurityMasks.Sacl); changed |= SecurityMasks.Sacl; }
        if (changed == 0 && flags == Descriptor.Control) return this;
        var next = DescriptorRewriter.Rewrite(Descriptor, flags, replacements);
        if (next.GetBinaryForm().AsSpan().SequenceEqual(Descriptor.GetBinaryForm())) return this;
        return new AclMutationEngine(next, OriginalDescriptor, WriteIntent | changed,
            (replaced & SecurityMasks.Dacl) == 0 ? _projectedDacl : null,
            (replaced & SecurityMasks.Sacl) == 0 ? _projectedSacl : null);
    }

    internal AclMutationEngine CopyAclProvenance(AclMutationEngine source, SecurityMasks section)
    {
        var state = source.RetainedState(section);
        if (state is null || ReferenceEquals(state, RetainedState(section))) return this;
        var acl = section == SecurityMasks.Dacl ? Descriptor.Dacl : Descriptor.Sacl;
        if (acl is null) throw new InvalidOperationException("Missing copied ACL storage.");
        ValidateProvenance(acl, state);
        return new AclMutationEngine(Descriptor, OriginalDescriptor, WriteIntent,
            section == SecurityMasks.Dacl ? state : _projectedDacl,
            section == SecurityMasks.Sacl ? state : _projectedSacl);
    }

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
        return new(new AclMutationEngine(descriptor, OriginalDescriptor, WriteIntent | section, _projectedDacl, _projectedSacl), returned, modified);
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
        var projected = MicrosoftObservableProjector.NormalizeForEdit(cleanHeader, isDacl).Aces.ToList();
        // Recognized common/object OI flags use the recorded DS scope rules. Scope()
        // retains invalid propagation as a failed operation rather than discarding data;
        // only the reviewed D13 normalization above may remove an inactive ACE.
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
            if (!TryMerge(aces[i], rule, out var merged)) continue;
            aces[i] = merged;
            return;
        }
        // Microsoft appends, then sorts. Inserting directly at the sorted position
        // loses its measured equal-key tie movement among existing known entries.
        aces.Add(rule);
        AclCanonicalizer.Sort(aces, isDacl);
    }

    internal static bool TryMerge(Ace ace, Ace rule, out Ace merged)
    {
        merged = ace;
        if (!Explicit(ace) || !Explicit(rule) || ace.AceType != rule.AceType || !SameSid(ace, rule)) return false;
        // Microsoft compares GUID values locally during merging, while
        // asymmetric absorption checks actual presence bits. Never rewrite the
        // existing GUID layout or apply this equivalence to raw identity.
        var objectTypesMatch = ace.ObjectType.GetValueOrDefault() == rule.ObjectType.GetValueOrDefault();
        var inheritedTypesMatch = ace.InheritedObjectType.GetValueOrDefault() == rule.InheritedObjectType.GetValueOrDefault();
        var masksMergeable = objectTypesMatch
            || ((ace.ObjectFlags & Ace.ObjectTypePresent) == 0
                && (ace.AccessMask & rule.AccessMask & ObjectQualifiedRights)
                == (rule.AccessMask & ObjectQualifiedRights));
        // Stage 1: identical flags and inherited GUID values; OR the masks.
        if (ace.AceFlags == rule.AceFlags && inheritedTypesMatch && masksMergeable)
        {
            merged = With(ace, ace.AccessMask | rule.AccessMask, ace.AceFlags);
            return true;
        }
        if (ace.AccessMask != rule.AccessMask) return false;
        // Stage 2: identical inheritance and GUID values; combine audit flags.
        if (objectTypesMatch && inheritedTypesMatch
            && (ace.AceFlags & 0x0F) == (rule.AceFlags & 0x0F))
        {
            merged = With(ace, ace.AccessMask, (byte)(ace.AceFlags | rule.AceFlags));
            return true;
        }
        // Stage 3: equal rights/audit; absent existing IOT permits asymmetric
        // scope absorption. Only this stage recalculates DS propagation flags.
        if (objectTypesMatch && (inheritedTypesMatch || (ace.ObjectFlags & Ace.InheritedObjectTypePresent) == 0)
            && (ace.AceFlags & 0xC0) == (rule.AceFlags & 0xC0)
            && Scope(ace) >= 0 && Scope(rule) >= 0
            && TryFlags(Scope(ace) | Scope(rule), out var flags))
        {
            merged = With(ace, ace.AccessMask, (byte)((ace.AceFlags & 0xC0) | flags));
            return true;
        }
        return false;
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
