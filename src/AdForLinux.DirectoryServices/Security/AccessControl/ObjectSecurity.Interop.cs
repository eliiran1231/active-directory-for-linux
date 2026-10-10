using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using C = AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.Security.AccessControl;

// Internal companion boundary only. Neither value contains a facade, resolver, owner,
// connection, callback or persistence capability. Byte access always returns a copy.
internal sealed class InteropSnapshot
{
    private readonly byte[] raw, original, observable;
    internal InteropSnapshot(Guid source, long generation, long attachment, byte[] raw,
        byte[] original, byte[] observable, SecurityMasks retrieved, SecurityMasks pending,
        bool container, bool directory)
    {
        Source = source; Generation = generation; Attachment = attachment;
        this.raw = raw.ToArray(); this.original = original.ToArray(); this.observable = observable.ToArray();
        Retrieved = retrieved; Pending = pending; IsContainer = container; IsDirectory = directory;
    }
    internal Guid Source { get; }
    internal long Generation { get; }
    internal long Attachment { get; }
    internal SecurityMasks Retrieved { get; }
    internal SecurityMasks Pending { get; }
    internal bool IsContainer { get; }
    internal bool IsDirectory { get; }
    internal byte[] Raw => raw.ToArray();
    internal byte[] Original => original.ToArray();
    internal byte[] Observable => observable.ToArray();
}

internal sealed class InteropBaseline
{
    private readonly byte[] baseline;
    internal InteropBaseline(InteropSnapshot snapshot, byte[] baseline)
    { Snapshot = snapshot; this.baseline = baseline.ToArray(); }
    internal InteropSnapshot Snapshot { get; }
    internal byte[] Binary => baseline.ToArray();
}

public abstract partial class ObjectSecurity
{
    private readonly Guid interopSource = Guid.NewGuid();
    private const SecurityMasks InteropAll = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;

    internal InteropSnapshot CaptureInteropSnapshot()
    {
        ReadLock();
        try
        {
            lock (FacadeMutation.Gate)
                return new(interopSource, _securityDescriptor.MutationVersion, identityAttachment,
                    _securityDescriptor.MutationState.Descriptor.GetBinaryForm(),
                    (_readContext?.Original ?? _securityDescriptor.MutationState.OriginalDescriptor).GetBinaryForm(),
                    FacadeMutation.Bytes(_securityDescriptor), InteropCoverage, PendingWriteSections, IsContainer, IsDS);
        }
        finally { ReadUnlock(); }
    }

    // An AD wrapper may describe explicit partial import coverage without carrying
    // a server read context. Never promote that coverage to All from stored bytes.
    private SecurityMasks InteropCoverage => this is ActiveDirectorySecurity ad
        ? RetrievedSections & ad.RetrievedMasks : RetrievedSections;

    // The optional companion supplies the actual Microsoft constructor/serializer.
    // They execute outside all portable locks and are never retained in provenance.
    internal T ExportDetachedInterop<T>(Func<byte[], bool, bool, T> construct, Func<T, byte[]> serialize)
        => ExportInterop(construct, serialize).Value;

    internal (T Value, InteropBaseline Provenance) ExportInterop<T>(
        Func<byte[], bool, bool, T> construct, Func<T, byte[]> serialize)
    {
        ArgumentNullException.ThrowIfNull(construct);
        ArgumentNullException.ThrowIfNull(serialize);
        if (_lock.IsReadLockHeld || _lock.IsWriteLockHeld || Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("External conversion cannot run while the caller holds a portable security lock.");
        var snapshot = CaptureInteropSnapshot();
        return ExportInteropSnapshot(snapshot, construct, serialize);
    }

    internal static (T Value, InteropBaseline Provenance) ExportInteropSnapshot<T>(InteropSnapshot snapshot,
        Func<byte[], bool, bool, T> construct, Func<T, byte[]> serialize)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(construct);
        ArgumentNullException.ThrowIfNull(serialize);
        if (Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("External conversion cannot run inside the portable mutation gate.");
        if (snapshot.Retrieved != InteropAll)
            throw new NotSupportedException("A complete Microsoft descriptor export cannot represent unread sections.");
        var raw = C.SecurityDescriptor.Parse(snapshot.Raw, InteropAll);
        ValidateInteropLayout(raw);
        // Validate raw contributors independently: a normalized live view cannot prove
        // that omitted opaque data was harmless. Reuse only the reviewed allowlist.
        _ = C.MicrosoftObservableProjector.Project(raw);
        var observable = C.SecurityDescriptor.Parse(snapshot.Observable, InteropAll);
        var expected = C.MicrosoftObservableProjector.Project(observable).GetBinaryForm();
        var value = construct(snapshot.Observable, snapshot.IsContainer, snapshot.IsDirectory);
        var actual = CanonicalInteropImage(serialize(value));
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new NotSupportedException("The Microsoft import changed data outside the verified projection contract.");
        return (value, new(snapshot, actual));
    }

    internal static void ValidateInteropImport(byte[] native, byte[] portable)
    {
        // Validate source storage before comparing actual serialized results. Import
        // cannot recover already-lost native data, or drop more while crossing back.
        _ = C.MicrosoftObservableProjector.Project(C.SecurityDescriptor.Parse(native, InteropAll));
        if (!CanonicalInteropImage(native).AsSpan().SequenceEqual(CanonicalInteropImage(portable)))
            throw new NotSupportedException("Portable import changed the Microsoft descriptor serialization.");
    }

    // A detached buffer is never sufficient provenance. Only this source wrapper at
    // the captured generation may reconcile. ACL edits require the independently
    // verified unique-contributor edit mapping; replacement is not a fallback.
    internal SecurityMasks ReconcileInterop(InteropBaseline provenance, byte[] edited)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(edited);
        var candidate = CanonicalInteropImage(edited);
        var baseline = provenance.Binary;
        var snapshot = provenance.Snapshot;
        if (Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("Interop publication cannot start inside the portable mutation gate.");
        // Borrow only the caller-supplied wrapper's current resolver. The session
        // retains no authority. Lock order matches identity mutation publication:
        // wrapper write lock, binding lifetime, then the shared mutation gate.
        var read = CaptureIdentityRead();
        WriteLock();
        try
        {
            SecurityMasks Publish(IdentityReadOrigin? origin) => FacadeMutation.Run(() =>
            {
                if (snapshot.Source != interopSource || snapshot.Generation != _securityDescriptor.MutationVersion
                    || snapshot.Attachment != identityAttachment || read.Attachment != identityAttachment
                    || !ReferenceEquals(read.Resolver, identityResolver))
                    throw new InvalidOperationException("The export provenance is unrelated or stale.");
                if (HasRawReadContext && (origin is null || RawReadOrigin != origin))
                    throw new InvalidOperationException("The current binding does not own the retained raw read origin.");
                if (snapshot.Retrieved != InteropAll)
                    throw new NotSupportedException("Unread sections cannot be inferred from a Microsoft descriptor.");
                if (candidate.AsSpan().SequenceEqual(baseline)) return SecurityMasks.None;
                if (!candidate.AsSpan(0, 4).SequenceEqual(baseline.AsSpan(0, 4)))
                    throw new NotSupportedException("Control-field edit-back requires explicit operation provenance.");
                var changed = SecurityMasks.None;
                CaptureDirtyFlags();
                for (var i = 2; i < 4; i++)
                {
                    if (InteropComponent(candidate, i).SequenceEqual(InteropComponent(baseline, i))) continue;
                    var acl = i == 2 ? (CommonAcl?)_securityDescriptor.SystemAcl : _securityDescriptor.DiscretionaryAcl;
                    if (acl is null || InteropComponent(candidate, i).IsEmpty || InteropComponent(baseline, i).IsEmpty)
                        throw new NotSupportedException("ACL state transitions require explicit operation provenance.");
                    acl.ReconcileInteropEdits(InteropComponent(baseline, i).ToArray(), InteropComponent(candidate, i).ToArray());
                    if (i == 2) { _saclModified = true; changed |= SecurityMasks.Sacl; }
                    else { _daclModified = true; changed |= SecurityMasks.Dacl; }
                }
                for (var i = 0; i < 2; i++)
                {
                    if (InteropComponent(candidate, i).SequenceEqual(InteropComponent(baseline, i))) continue;
                    var bytes = InteropComponent(candidate, i).ToArray();
                    var sid = bytes.Length == 0 ? null : new SecurityIdentifier(bytes, 0);
                    if (i == 0) { _securityDescriptor.Owner = sid; _ownerModified = true; changed |= SecurityMasks.Owner; }
                    else { _securityDescriptor.Group = sid; _groupModified = true; changed |= SecurityMasks.Group; }
                }
                return changed;
            });
            // This checked scope holds the owner's lifetime through publication,
            // including a no-op. No lookup, transport, virtual hook or caller factory
            // runs here. Revocation either precedes the edit or follows its completion.
            return read.Resolver is null ? Publish(null) : read.Resolver.Checked(() =>
                Publish(HasRawReadContext ? read.Resolver.GetReadOrigin() : null));
        }
        finally { WriteUnlock(); }
    }

    private static ReadOnlySpan<byte> InteropComponent(byte[] image, int index)
    {
        var offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(4 + index * 4)));
        if (offset == 0) return [];
        var length = index < 2 ? 8 + image[offset + 1] * 4 : BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset + 2));
        return image.AsSpan(offset, length);
    }

    private static byte[] CanonicalInteropImage(byte[] image)
    {
        var parsed = C.SecurityDescriptor.Parse(image, InteropAll);
        ValidateInteropLayout(parsed);
        return C.DescriptorRewriter.RepackObservable(parsed, parsed.Control, new Dictionary<SecurityMasks, byte[]?>()).GetBinaryForm();
    }

    private static void ValidateInteropLayout(C.SecurityDescriptor descriptor)
    {
        var image = descriptor.GetBinaryForm();
        // Preserve meaningful fields by refusing unsupported export rather than letting
        // a Microsoft setter silently clear them. Repacking referenced storage is allowed.
        if (descriptor.Sbz1 != 0 || (descriptor.Control & ~0xbc14) != 0
            || descriptor.HasAclDataWithoutPresentBit(SecurityMasks.Dacl)
            || descriptor.HasAclDataWithoutPresentBit(SecurityMasks.Sacl))
            throw new NotSupportedException("Microsoft conversion of these descriptor fields is not verified.");
        var covered = new bool[image.Length]; Array.Fill(covered, true, 0, 20);
        for (var i = 0; i < 4; i++)
        {
            var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(4 + i * 4));
            if (offset != 0) Array.Fill(covered, true, offset, InteropComponent(image, i).Length);
        }
        if (covered.Contains(false))
            throw new NotSupportedException("Microsoft conversion cannot discard unexplained descriptor storage.");
    }
}
