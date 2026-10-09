#pragma warning disable CA1416
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using C = AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.Security.AccessControl;

// A detached transaction gate, never an identity resolver or persistence capability.
// Wrapper compatibility locks remain separate. The ambient undo list makes compound
// helper calls atomic, including edits to an ACL shared by multiple descriptors.
internal static class FacadeMutation
{
    internal static readonly object Gate = new();
    [ThreadStatic] private static Stack<Dictionary<object, Action>>? scopes;
    internal static void Capture(object value, Func<Action> snapshot)
    {
        // Every nested operation is a savepoint: an override may catch a failed edit
        // and continue, but the failed operation still must not leave staged state.
        if (scopes is null) return;
        foreach (var undo in scopes.Reverse())
            if (!undo.ContainsKey(value)) undo.Add(value, snapshot());
    }
    internal static T Run<T>(Func<T> action)
    {
        lock (Gate)
        {
            scopes ??= new();
            var undo = new Dictionary<object, Action>(ReferenceEqualityComparer.Instance);
            scopes.Push(undo);
            try { return action(); }
            catch { foreach (var rollback in undo.Values.Reverse()) rollback(); throw; }
            finally { scopes.Pop(); }
        }
    }
    internal static void Run(Action action) => Run(() => { action(); return true; });
    internal static byte[] Bytes(GenericSecurityDescriptor descriptor)
    { var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0); return bytes; }
    internal static byte[] Bytes(GenericAcl acl)
    { var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes; }
    internal static C.Sid Sid(SecurityIdentifier sid)
    { var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); if (!C.Sid.TryRead(bytes, out var result, out _)) throw new ArgumentException("Invalid SID.", nameof(sid)); return result!; }

    internal static void ValidateSectionImport(RawSecurityDescriptor descriptor)
    {
        // Section setters cannot assign unreferenced descriptor storage or the resource
        // manager byte. Refuse such input instead of silently losing it while extracting
        // components. Raw/common binary constructors retain the complete image.
        var bytes = descriptor.PreservedInput();
        var parsed = C.SecurityDescriptor.Parse(bytes, SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl);
        // These are precisely the control fields carried by the native section setter,
        // plus the self-relative format bit. Other nonzero input fields must not vanish.
        const ushort assignableControl = 0xbc14;
        if (bytes[1] != 0 || (parsed.Control & ~assignableControl) != 0
            || parsed.HasAclDataWithoutPresentBit(SecurityMasks.Dacl) || parsed.HasAclDataWithoutPresentBit(SecurityMasks.Sacl))
            throw new NotSupportedException("This descriptor contains storage that a section setter cannot assign losslessly.");
        var covered = new bool[bytes.Length]; Array.Fill(covered, true, 0, 20);
        for (var i = 0; i < 4; i++)
        {
            var offset = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4 + i * 4));
            if (offset == 0) continue;
            var length = i < 2 ? 8 + bytes[offset + 1] * 4
                : System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 2));
            Array.Fill(covered, true, offset, length);
        }
        if (covered.Contains(false)) throw new NotSupportedException("Section assignment cannot discard unexplained descriptor storage.");
    }
}

public abstract partial class CommonAcl
{
    private readonly List<WeakReference<CommonSecurityDescriptor>> owners = new();
    internal C.AclMutationEngine? RetainedMutation { get; private set; }
    internal void Retain(C.AclMutationEngine state) => RetainedMutation = state;
    internal void Attach(CommonSecurityDescriptor descriptor)
    {
        owners.RemoveAll(w => !w.TryGetTarget(out _));
        if (!owners.Any(w => w.TryGetTarget(out var d) && ReferenceEquals(d, descriptor))) owners.Add(new(descriptor));
    }
    internal Action CaptureFacade()
    {
        var raw = _acl; var dirty = _isDirty; var retained = RetainedMutation;
        var nullDacl = this is DiscretionaryAcl d && d.EveryOneFullAccessForNullDacl;
        _acl = new RawAcl(FacadeMutation.Bytes(raw), 0);
        return () => { _acl = raw; _isDirty = dirty; RetainedMutation = retained; if (this is DiscretionaryAcl restored) restored.EveryOneFullAccessForNullDacl = nullDacl; };
    }
    private T Edit<T>(Func<C.AclMutationEngine, SecurityMasks, C.AclMutationEngine> plan, Func<T> action)
        => FacadeMutation.Run(() =>
        {
            FacadeMutation.Capture(this, CaptureFacade);
            var affected = owners.Select(w => w.TryGetTarget(out var d) ? d : null)
                .Where(d => d is not null && (ReferenceEquals(d.DiscretionaryAcl, this) || ReferenceEquals(d.SystemAcl, this))).Cast<CommonSecurityDescriptor>().ToArray();
            var before = FacadeMutation.Bytes(this);
            var nullBefore = this is DiscretionaryAcl d && d.EveryOneFullAccessForNullDacl;
            var result = action();
            var after = FacadeMutation.Bytes(this);
            var nullAfter = this is DiscretionaryAcl a && a.EveryOneFullAccessForNullDacl;
            if (!before.AsSpan().SequenceEqual(after) || nullBefore != nullAfter)
            {
                foreach (var descriptor in affected) descriptor.ApplyAcl(this, plan, after);
                if (affected.Length == 0 && RetainedMutation is { } retained)
                {
                    var section = this is DiscretionaryAcl ? SecurityMasks.Dacl : SecurityMasks.Sacl;
                    var next = plan(retained, section);
                    var acl = next.GetObservableAcl(section);
                    if (acl is null) throw new InvalidOperationException("Missing detached ACL projection.");
                    var bytes = new byte[acl.BinaryLength]; acl.WriteTo(bytes);
                    if (!bytes.AsSpan().SequenceEqual(after)) throw new InvalidOperationException("Unverified detached ACL edit.");
                    Retain(next);
                }
            }
            return result;
        });
    private void Edit(Func<C.AclMutationEngine, SecurityMasks, C.AclMutationEngine> plan, Action action)
        => Edit(plan, () => { action(); return true; });
    internal void ReconcileInteropMasks(byte[] baseline, byte[] edited)
        => Edit((engine, section) => engine.ReconcileInteropMasks(section, baseline, edited),
            () => { _acl = new RawAcl(edited, 0); _isDirty = false; });
    // Protection also exposes the synthetic Everyone ACL. Treat that marker-only
    // transition as an ACL edit so all owners reconcile or roll back together.
    internal void MaterializeNullDacl()
        => Edit((engine, section) => engine.SetProtectionProjected(section,
            (engine.Descriptor.Control & 0x1000) != 0, true).Engine,
            () => { if (this is DiscretionaryAcl dacl) dacl.EveryOneFullAccessForNullDacl = false; });
    private C.Ace Rule(SecurityIdentifier sid, AceQualifier qualifier, int mask, AceFlags flags,
        ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
    {
        GenericAce ace = !IsDS || objectFlags == ObjectAceFlags.None
            ? new CommonAce(flags, qualifier, mask, sid, false, null)
            : new ObjectAce(flags, qualifier, mask, sid, objectFlags, objectType, inheritedObjectType, false, null);
        if (!InspectAce(ref ace, this is DiscretionaryAcl)) throw new InvalidOperationException("The rule has no observable form.");
        var bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); return C.Ace.Read(bytes);
    }
}

public sealed partial class CommonSecurityDescriptor
{
    private int assignmentDepth;
    internal C.AclMutationEngine MutationState { get; private set; } = null!;
    // Independent of every ObjectSecurity wrapper's native dirty flags.
    internal long MutationVersion { get; private set; }
    private long[] sectionVersions = new long[4];
    private static readonly SecurityMasks[] sections = [SecurityMasks.Owner, SecurityMasks.Group, SecurityMasks.Sacl, SecurityMasks.Dacl];
    internal SecurityMasks ChangesSince(long version)
    {
        lock (FacadeMutation.Gate)
        {
            var result = SecurityMasks.None;
            for (var i = 0; i < sections.Length; i++) if (sectionVersions[i] > version) result |= sections[i];
            return result;
        }
    }
    private void InitializeMutation(byte[] binary, bool copyProvenance = false)
    {
        MutationState = new C.AclMutationEngine(C.SecurityDescriptor.Parse(binary,
            SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl));
        if (copyProvenance && _dacl?.RetainedMutation is { } dacl) MutationState = MutationState.CopyAclProvenance(dacl, SecurityMasks.Dacl);
        if (copyProvenance && _sacl?.RetainedMutation is { } sacl) MutationState = MutationState.CopyAclProvenance(sacl, SecurityMasks.Sacl);
        _dacl?.Attach(this); _sacl?.Attach(this);
    }
    internal Action CaptureFacade()
    {
        var dacl = _dacl; var sacl = _sacl; var state = MutationState; var version = MutationVersion;
        var versions = (long[])sectionVersions.Clone();
        var owner = _rawSd.Owner; var group = _rawSd.Group; var flags = _rawSd.ControlFlags;
        return () => { _dacl = dacl; _sacl = sacl; MutationState = state; MutationVersion = version; sectionVersions = versions;
            _rawSd.Owner = owner; _rawSd.Group = group; _rawSd.SetFlags(flags);
            _rawSd.DiscretionaryAcl = dacl?.RawAcl; _rawSd.SystemAcl = sacl?.RawAcl; };
    }
    private void Publish(C.AclMutationEngine state)
    {
        if (ReferenceEquals(state, MutationState)) return;
        var before = MutationState.Descriptor.GetBinaryForm();
        var after = state.Descriptor.GetBinaryForm();
        var flags = MutationState.Descriptor.Control ^ state.Descriptor.Control;
        MutationState = state; MutationVersion++;
        for (var i = 0; i < sections.Length; i++)
            if (!Component(before, i).SequenceEqual(Component(after, i))
                || (i == 2 && (flags & 0x2a10) != 0) || (i == 3 && (flags & 0x1504) != 0))
                sectionVersions[i] = MutationVersion;

        static ReadOnlySpan<byte> Component(byte[] bytes, int index)
        {
            var offset = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4 + index * 4));
            if (offset == 0) return [];
            var length = index < 2 ? 8 + bytes[offset + 1] * 4
                : System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 2));
            return bytes.AsSpan(offset, length);
        }
    }
    internal void ApplyAcl(CommonAcl acl, Func<C.AclMutationEngine, SecurityMasks, C.AclMutationEngine> plan, byte[] expected)
    {
        FacadeMutation.Capture(this, CaptureFacade);
        var section = ReferenceEquals(acl, _dacl) ? SecurityMasks.Dacl : SecurityMasks.Sacl;
        var next = plan(MutationState, section);
        var observable = next.GetObservableAcl(section);
        if (observable is null) throw new InvalidOperationException("The candidate ACL has no observable form.");
        var bytes = new byte[observable.BinaryLength]; observable.WriteTo(bytes);
        if (!bytes.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException("The facade edit is outside the verified raw/live reconciliation contract.");
        Publish(next);
        acl.Retain(next);
        _rawSd.DiscretionaryAcl = _dacl?.RawAcl; _rawSd.SystemAcl = _sacl?.RawAcl;
    }
    private void Assign(SecurityMasks section, Action action)
        => FacadeMutation.Run(() =>
        {
            FacadeMutation.Capture(this, CaptureFacade);
            assignmentDepth++;
            try { action(); }
            finally { assignmentDepth--; }
            byte[]? bytes = null; ushort mask = 0;
            if (section is SecurityMasks.Owner or SecurityMasks.Group)
            {
                var sid = section == SecurityMasks.Owner ? Owner : Group;
                if (sid is not null) { bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0); }
            }
            else
            {
                var acl = section == SecurityMasks.Dacl ? (CommonAcl?)_dacl : _sacl;
                if (acl is not null && !(acl is DiscretionaryAcl d && d.EveryOneFullAccessForNullDacl)) bytes = acl.PreservedInput();
                mask = (ushort)(section == SecurityMasks.Dacl ? 0x1504 : 0x2a10);
                acl?.Attach(this);
            }
            var next = MutationState.ReplaceSections(new Dictionary<SecurityMasks, byte[]?> { [section] = bytes }, mask, (ushort)ControlFlags);
            var assigned = section == SecurityMasks.Dacl ? (CommonAcl?)_dacl : section == SecurityMasks.Sacl ? _sacl : null;
            if (assigned?.RetainedMutation is { } retained) next = next.CopyAclProvenance(retained, section);
            Publish(next);
        });
    private void ChangeFlags(ushort mask, Action action)
        => FacadeMutation.Run(() =>
        {
            FacadeMutation.Capture(this, CaptureFacade); action();
            if (assignmentDepth != 0) return;
            Publish(MutationState.ReplaceSections(new Dictionary<SecurityMasks, byte[]?>(), mask, (ushort)ControlFlags));
        });
}
