using System.Buffers.Binary;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Edits only the two explicit change-password ACEs used by Active Directory.
/// This avoids the Windows-only ObjectSecurity API while preserving every
/// unrelated byte in the self-relative security descriptor.
/// </summary>
internal static class ChangePasswordAcl
{
    private const byte AccessAllowedObjectAceType = 0x05;
    private const byte AccessDeniedObjectAceType = 0x06;
    private const uint ControlAccess = 0x00000100;
    private const uint ObjectTypePresent = 0x00000001;
    private const int DaclOffsetField = 16;
    private static readonly Guid ChangePasswordRight = new("ab721a53-1e2f-11d0-9819-00aa0040529b");
    private static readonly byte[] SelfSid = { 1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0 };
    private static readonly byte[] WorldSid = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };

    internal static bool IsDenied(byte[] descriptor)
    {
        var acl = ReadAcl(descriptor);
        return acl.Aces.Any(ace => IsTarget(ace, AccessDeniedObjectAceType, SelfSid))
            || acl.Aces.Any(ace => IsTarget(ace, AccessDeniedObjectAceType, WorldSid));
    }

    internal static byte[] SetDenied(byte[] descriptor, bool denied)
    {
        var acl = ReadAcl(descriptor);
        var retained = acl.Aces
            .Where(ace => !IsTarget(ace, AccessAllowedObjectAceType, SelfSid)
                && !IsTarget(ace, AccessAllowedObjectAceType, WorldSid)
                && !IsTarget(ace, AccessDeniedObjectAceType, SelfSid)
                && !IsTarget(ace, AccessDeniedObjectAceType, WorldSid))
            .ToList();
        var aceType = denied ? AccessDeniedObjectAceType : AccessAllowedObjectAceType;
        var replacementAces = new[] { BuildAce(aceType, SelfSid), BuildAce(aceType, WorldSid) };

        // Explicit deny ACEs are canonical before allows. Explicit allows are
        // canonical after any existing denies and before inherited ACEs.
        var insertion = denied
            ? 0
            : retained.FindIndex(ace => (ace[1] & 0x10) != 0);
        if (insertion < 0)
        {
            insertion = retained.Count;
        }

        retained.InsertRange(insertion, replacementAces);
        var newAclSize = 8 + retained.Sum(ace => ace.Length);
        var newAcl = new byte[newAclSize];
        descriptor.AsSpan(acl.Offset, 8).CopyTo(newAcl);
        BinaryPrimitives.WriteUInt16LittleEndian(newAcl.AsSpan(2), checked((ushort)newAclSize));
        BinaryPrimitives.WriteUInt16LittleEndian(newAcl.AsSpan(4), checked((ushort)retained.Count));
        var cursor = 8;
        foreach (var ace in retained)
        {
            ace.CopyTo(newAcl, cursor);
            cursor += ace.Length;
        }

        return ReplaceAcl(descriptor, acl.Offset, acl.Size, newAcl);
    }

    private static (int Offset, int Size, List<byte[]> Aces) ReadAcl(byte[] descriptor)
    {
        if (descriptor.Length < 20)
        {
            throw new InvalidOperationException("The security descriptor is truncated.");
        }

        var offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(DaclOffsetField)));
        if (offset == 0 || offset + 8 > descriptor.Length)
        {
            throw new InvalidOperationException("The security descriptor has no readable DACL.");
        }

        var size = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(offset + 2));
        var count = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(offset + 4));
        if (size < 8 || offset + size > descriptor.Length)
        {
            throw new InvalidOperationException("The security descriptor DACL is truncated.");
        }

        var aces = new List<byte[]>(count);
        var cursor = offset + 8;
        for (var i = 0; i < count; i++)
        {
            if (cursor + 4 > offset + size)
            {
                throw new InvalidOperationException("The security descriptor ACE list is truncated.");
            }

            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(cursor + 2));
            if (aceSize < 4 || cursor + aceSize > offset + size)
            {
                throw new InvalidOperationException("The security descriptor contains an invalid ACE.");
            }

            aces.Add(descriptor.AsSpan(cursor, aceSize).ToArray());
            cursor += aceSize;
        }

        return (offset, size, aces);
    }

    private static bool IsTarget(byte[] ace, byte type, byte[] sid)
    {
        if (ace.Length < 28 || ace[0] != type || ace[1] != 0)
        {
            return false;
        }

        var mask = BinaryPrimitives.ReadUInt32LittleEndian(ace.AsSpan(4));
        var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(ace.AsSpan(8));
        if ((mask & ControlAccess) == 0 || (objectFlags & ObjectTypePresent) == 0)
        {
            return false;
        }

        var objectType = new Guid(ace.AsSpan(12, 16));
        var sidOffset = 28 + ((objectFlags & 0x2) != 0 ? 16 : 0);
        return objectType == ChangePasswordRight
            && ace.AsSpan(sidOffset).SequenceEqual(sid);
    }

    private static byte[] BuildAce(byte type, byte[] sid)
    {
        var ace = new byte[28 + sid.Length];
        ace[0] = type;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), ControlAccess);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(8), ObjectTypePresent);
        ChangePasswordRight.TryWriteBytes(ace.AsSpan(12, 16));
        sid.CopyTo(ace, 28);
        return ace;
    }

    private static byte[] ReplaceAcl(byte[] descriptor, int offset, int oldSize, byte[] acl)
    {
        var delta = acl.Length - oldSize;
        var result = new byte[descriptor.Length + delta];
        descriptor.AsSpan(0, offset).CopyTo(result);
        acl.CopyTo(result, offset);
        descriptor.AsSpan(offset + oldSize).CopyTo(result.AsSpan(offset + acl.Length));

        foreach (var field in new[] { 4, 8, 12 })
        {
            var componentOffset = BinaryPrimitives.ReadUInt32LittleEndian(result.AsSpan(field));
            if (componentOffset > offset)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    result.AsSpan(field), checked((uint)(componentOffset + delta)));
            }
        }

        return result;
    }
}
