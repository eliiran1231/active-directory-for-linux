using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>Builds independent component storage, then validates the complete image before publication.</summary>
internal static class DescriptorRewriter
{
    internal static SecurityDescriptor Rewrite(SecurityDescriptor source, ushort control,
        IReadOnlyDictionary<SecurityMasks, byte[]?> replacements)
    {
        var image = source.GetBinaryForm();
        var sections = new[] { SecurityMasks.Owner, SecurityMasks.Group, SecurityMasks.Sacl, SecurityMasks.Dacl };
        var components = new byte[]?[4];
        var covered = new bool[image.Length];
        Array.Fill(covered, true, 0, SecurityDescriptor.HeaderLength);
        for (var i = 0; i < sections.Length; i++)
        {
            var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(4 + i * 4));
            if (offset != 0)
            {
                var length = i < 2 ? 8 + image[offset + 1] * 4
                    : BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset + 2));
                components[i] = image.AsSpan(offset, length).ToArray();
                Array.Fill(covered, true, offset, length);
            }
            if (replacements.TryGetValue(sections[i], out var replacement))
                components[i] = replacement;
        }
        // There is no approved interpretation or relocation rule for unreferenced payloads.
        if (covered.Any(value => !value))
            throw new InvalidOperationException("Cannot relocate unexplained descriptor gap or trailing bytes.");
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
