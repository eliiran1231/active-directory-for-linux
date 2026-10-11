using System.Buffers.Binary;
using AdForLinux.DirectoryServices;
using C = AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.Security.AccessControl;

// Internal export snapshot only. This value contains no facade, resolver, owner,
// connection, callback or persistence capability. Byte access always returns a copy.
internal sealed class InteropSnapshot
{
    private readonly byte[] raw, original, observable;
    internal InteropSnapshot(long generation, byte[] raw,
        byte[] original, byte[] observable, SecurityMasks retrieved, SecurityMasks pending,
        bool container, bool directory)
    {
        Generation = generation;
        this.raw = raw.ToArray(); this.original = original.ToArray(); this.observable = observable.ToArray();
        Retrieved = retrieved; Pending = pending; IsContainer = container; IsDirectory = directory;
    }
    internal long Generation { get; }
    internal SecurityMasks Retrieved { get; }
    internal SecurityMasks Pending { get; }
    internal bool IsContainer { get; }
    internal bool IsDirectory { get; }
    internal byte[] Raw => raw.ToArray();
    internal byte[] Original => original.ToArray();
    internal byte[] Observable => observable.ToArray();
}

public abstract partial class ObjectSecurity
{
    private const SecurityMasks InteropAll = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;

    internal InteropSnapshot CaptureInteropSnapshot()
    {
        ReadLock();
        try
        {
            lock (FacadeMutation.Gate)
                return new(_securityDescriptor.MutationVersion,
                    _securityDescriptor.MutationState.Descriptor.GetBinaryForm(),
                    (_readContext?.Original ?? _securityDescriptor.MutationState.OriginalDescriptor).GetBinaryForm(),
                    FacadeMutation.Bytes(_securityDescriptor), InteropCoverage, PendingWriteSections, IsContainer, IsDS);
        }
        finally { ReadUnlock(); }
    }

    // An AD wrapper may describe explicit partial retrieved coverage without carrying
    // a server read context. Never promote that coverage to All from stored bytes.
    private SecurityMasks InteropCoverage => this is ActiveDirectorySecurity ad
        ? RetrievedSections & ad.RetrievedMasks : RetrievedSections;

    // The optional companion supplies the actual Microsoft constructor/serializer.
    // They execute outside all portable locks and are never retained by the snapshot.
    internal T ExportDetachedInterop<T>(
        Func<byte[], bool, bool, T> construct, Func<T, byte[]> serialize)
    {
        ArgumentNullException.ThrowIfNull(construct);
        ArgumentNullException.ThrowIfNull(serialize);
        if (_lock.IsReadLockHeld || _lock.IsWriteLockHeld || Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("External conversion cannot run while the caller holds a portable security lock.");
        var snapshot = CaptureInteropSnapshot();
        return ExportInteropSnapshot(snapshot, construct, serialize);
    }

    internal static T ExportInteropSnapshot<T>(InteropSnapshot snapshot,
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
            throw new NotSupportedException("The Microsoft export changed data outside the verified projection contract.");
        return value;
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
