using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>Builds independent component storage, then validates the complete image before publication.</summary>
internal static class DescriptorRewriter
{
    internal static SecurityDescriptor Rewrite(SecurityDescriptor source, ushort control,
        IReadOnlyDictionary<SecurityMasks, byte[]?> replacements)
        => RewriteCore(source, control, replacements, observable: false);

    // Microsoft repacks the observable value. This is never a raw write candidate.
    internal static SecurityDescriptor RepackObservable(SecurityDescriptor source, ushort control,
        IReadOnlyDictionary<SecurityMasks, byte[]?> replacements)
        => RewriteCore(source, control, replacements, observable: true);

    private static SecurityDescriptor RewriteCore(SecurityDescriptor source, ushort control,
        IReadOnlyDictionary<SecurityMasks, byte[]?> replacements, bool observable)
    {
        var image = source.GetBinaryForm();
        var sections = new[] { SecurityMasks.Owner, SecurityMasks.Group, SecurityMasks.Sacl, SecurityMasks.Dacl };
        var originals = new byte[]?[4];
        var components = new byte[]?[4];
        var offsets = new int[4];
        var covered = new bool[image.Length];
        Array.Fill(covered, true, 0, SecurityDescriptor.HeaderLength);
        for (var i = 0; i < sections.Length; i++)
        {
            var offset = offsets[i] = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(4 + i * 4));
            if (offset != 0)
            {
                var length = i < 2 ? 8 + image[offset + 1] * 4
                    : BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset + 2));
                originals[i] = image.AsSpan(offset, length).ToArray();
                Array.Fill(covered, true, offset, length);
            }
            components[i] = replacements.TryGetValue(sections[i], out var replacement) ? replacement : originals[i];
        }
        if (!observable && covered.Any(value => !value))
            return PreserveLayout(source, control, image, originals, components, offsets, covered);

        var result = new byte[checked(20 + components.Sum(part => part?.Length ?? 0))];
        image.AsSpan(0, 4).CopyTo(result);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(2), control);
        var cursor = 20;
        for (var i = 0; i < components.Length; i++)
        {
            if (components[i] is not { } component) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4 + i * 4), (uint)cursor);
            component.CopyTo(result, cursor);
            cursor += component.Length;
        }
        return SecurityDescriptor.Parse(result, source.RetrievedSections);
    }

    private static SecurityDescriptor PreserveLayout(SecurityDescriptor source, ushort control,
        byte[] image, byte[]?[] originals, byte[]?[] components, int[] offsets, bool[] covered)
    {
        var relocated = new bool[4];
        var anchors = new List<int>();
        // Keep an outer referenced span in place. A contained alias can be copied to
        // independent storage without turning any of its old bytes into orphan data.
        foreach (var i in Enumerable.Range(0, 4).Where(i => originals[i] is not null)
            .OrderByDescending(i => originals[i]!.Length)
            .ThenBy(i => components[i] is not null && components[i]!.AsSpan().SequenceEqual(originals[i]) ? 0 : 1)
            .ThenByDescending(i => i))
        {
            var end = offsets[i] + originals[i]!.Length;
            foreach (var anchor in anchors)
            {
                var anchorEnd = offsets[anchor] + originals[anchor]!.Length;
                if (end <= offsets[anchor] || anchorEnd <= offsets[i]) continue;
                if (offsets[i] < offsets[anchor] || end > anchorEnd)
                    throw new InvalidOperationException("Crossing shared components with unexplained storage cannot be relocated safely.");
                relocated[i] = true;
                break;
            }
            if (!relocated[i]) anchors.Add(i);
        }
        var trailing = !covered[^1];
        var baseLength = image.Length;
        for (var i = 0; i < components.Length; i++)
        {
            if (originals[i] is null)
            {
                relocated[i] = components[i] is not null;
                continue;
            }
            if (components[i] is null)
                throw new InvalidOperationException("Removing a referenced component would change unexplained storage boundaries.");
            if (relocated[i] || originals[i]!.Length == components[i]!.Length) continue;
            if (offsets[i] + originals[i]!.Length != image.Length)
                throw new InvalidOperationException("An interior component cannot resize across fixed unexplained storage or another referenced component.");
            if (i >= 2 && !Acl.Read(originals[i]!).Trailing.IsEmpty)
                throw new InvalidOperationException("Resizing this layout would relocate unexplained ACL trailing data.");
            baseLength = checked(offsets[i] + components[i]!.Length);
        }
        if (trailing && relocated.Any(value => value))
            throw new InvalidOperationException("Appending independent storage would turn an unexplained descriptor trailer into an interior gap.");
        var destination = offsets.ToArray();
        var length = baseLength;
        for (var i = 0; i < components.Length; i++)
        {
            if (!relocated[i]) continue;
            length = checked((length + 3) & ~3);
            destination[i] = length;
            length = checked(length + components[i]!.Length);
        }
        var result = new byte[length];
        image.AsSpan(0, Math.Min(image.Length, baseLength)).CopyTo(result);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(2), control);
        for (var i = 0; i < components.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4 + i * 4), (uint)destination[i]);
            if (components[i] is { } component) component.CopyTo(result, destination[i]);
        }
        // Unexplained original bytes are retained at the same absolute positions, not
        // copied into an archive/trailer. No padding, including zero padding, is consumed.
        for (var i = 20; i < image.Length; i++)
            if (!covered[i] && (i >= result.Length || image[i] != result[i]))
                throw new InvalidOperationException("The candidate would move or overwrite unexplained descriptor storage.");
        var descriptor = SecurityDescriptor.Parse(result, source.RetrievedSections);
        if (descriptor.HasOverlappingComponents)
            throw new InvalidOperationException("The candidate still contains shared component storage.");
        return descriptor;
    }

    internal static byte[] EncodeAcl(Acl? baseline, IReadOnlyList<Ace> aces)
    {
        var length = 8L + aces.Sum(ace => (long)ace.Size) + (baseline?.Trailing.Length ?? 0);
        if (length > ushort.MaxValue || aces.Count > ushort.MaxValue)
            throw new InvalidOperationException("The resulting ACL exceeds its binary size limit.");
        var bytes = new byte[(int)length];
        bytes[0] = baseline?.AclRevision ?? Acl.RevisionDS;
        bytes[1] = baseline?.Sbz1 ?? 0;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), (ushort)length);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), (ushort)aces.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(6), baseline?.Sbz2 ?? 0);
        var cursor = 8;
        foreach (var ace in aces)
        {
            ace.RawBytes.CopyTo(bytes.AsSpan(cursor));
            cursor += ace.Size;
        }
        if (baseline is not null) baseline.Trailing.CopyTo(bytes.AsSpan(cursor));
        _ = Acl.Read(bytes);
        return bytes;
    }
}
