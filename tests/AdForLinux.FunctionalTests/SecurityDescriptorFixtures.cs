using System.Buffers.Binary;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Builds security-descriptor bytes directly, independent of the codec under test.
/// Mirrors the inputs used by the offline Windows oracle (docs/research/acl-windows-oracle).
/// </summary>
internal static class SecurityDescriptorFixtures
{
    public const ushort SelfRelative = 0x8000;
    public const ushort DaclPresent = 0x0004;
    public const ushort SaclPresent = 0x0010;

    public static readonly byte[] Everyone = Convert.FromHexString("010100000000000100000000");
    public static readonly byte[] Admins = Convert.FromHexString("01020000000000052000000020020000");
    public static readonly byte[] U1 = Convert.FromHexString("010500000000000515000000010000000200000003000000E9030000");
    public static readonly byte[] U2 = Convert.FromHexString("010500000000000515000000010000000200000003000000EA030000");
    public static readonly Guid G1 = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid G2 = Guid.Parse("22222222-2222-2222-2222-222222222222");

    /// <summary>Common ACE layout (types 0x00-0x03, callbacks 0x09/0x0A) with optional trailing data.</summary>
    public static byte[] Ace(byte type, byte flags, uint mask, byte[] sid, byte[]? tail = null)
    {
        tail ??= Array.Empty<byte>();
        var ace = new byte[8 + sid.Length + tail.Length];
        ace[0] = type;
        ace[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), mask);
        sid.CopyTo(ace, 8);
        tail.CopyTo(ace, 8 + sid.Length);
        return ace;
    }

    /// <summary>Object ACE layout; object flags are written raw so inconsistent combinations can be built.</summary>
    public static byte[] ObjAce(byte type, byte flags, uint mask, uint objectFlags, Guid? objectType,
        Guid? inheritedType, byte[] sid, byte[]? tail = null)
    {
        var body = new List<byte>(new byte[12]);
        body[0] = type;
        body[1] = flags;
        if (objectType is { } o) body.AddRange(o.ToByteArray());
        if (inheritedType is { } i) body.AddRange(i.ToByteArray());
        body.AddRange(sid);
        body.AddRange(tail ?? Array.Empty<byte>());
        var ace = body.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), mask);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(8), objectFlags);
        return ace;
    }

    public static byte[] Acl(byte revision, params byte[][] aces) => AclWithTail(revision, Array.Empty<byte>(), aces);

    /// <summary>ACL whose declared size also covers <paramref name="tail"/> after the last ACE.</summary>
    public static byte[] AclWithTail(byte revision, byte[] tail, params byte[][] aces)
    {
        var size = 8 + aces.Sum(a => a.Length) + tail.Length;
        var acl = new byte[size];
        acl[0] = revision;
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4), (ushort)aces.Length);
        var cursor = 8;
        foreach (var ace in aces)
        {
            ace.CopyTo(acl, cursor);
            cursor += ace.Length;
        }

        tail.CopyTo(acl, cursor);
        return acl;
    }

    public enum Part
    {
        Owner,
        Group,
        Sacl,
        Dacl,
    }

    /// <summary>
    /// Self-relative descriptor with components in owner, group, SACL, DACL order unless
    /// <paramref name="order"/> says otherwise, and optional gap bytes before each component.
    /// Present bits follow the arguments; <paramref name="nullDacl"/> sets DACL_PRESENT with offset 0.
    /// </summary>
    public static byte[] Build(byte[]? owner, byte[]? group, byte[]? dacl, byte[]? sacl = null,
        ushort extraControl = 0, bool nullDacl = false, Part[]? order = null, int gapBefore = 0,
        byte[]? tail = null, byte sbz1 = 0)
    {
        var control = (ushort)(SelfRelative | extraControl);
        if (dacl is not null || nullDacl) control |= DaclPresent;
        if (sacl is not null) control |= SaclPresent;
        var buffer = new List<byte>(new byte[20]);
        var offsets = new int[4];
        foreach (var part in order ?? new[] { Part.Owner, Part.Group, Part.Sacl, Part.Dacl })
        {
            var bytes = part switch
            {
                Part.Owner => owner,
                Part.Group => group,
                Part.Sacl => sacl,
                _ => dacl,
            };
            if (bytes is null) continue;
            for (var i = 0; i < gapBefore; i++) buffer.Add(0xEE);
            offsets[(int)part] = buffer.Count;
            buffer.AddRange(bytes);
        }

        buffer.AddRange(tail ?? Array.Empty<byte>());
        var sd = buffer.ToArray();
        sd[0] = 1;
        sd[1] = sbz1;
        BinaryPrimitives.WriteUInt16LittleEndian(sd.AsSpan(2), control);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(4), (uint)offsets[(int)Part.Owner]);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(8), (uint)offsets[(int)Part.Group]);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(12), (uint)offsets[(int)Part.Sacl]);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(16), (uint)offsets[(int)Part.Dacl]);
        return sd;
    }

    public static byte[] WithDacl(params byte[][] aces) => Build(Admins, Admins, Acl(4, aces));
}
