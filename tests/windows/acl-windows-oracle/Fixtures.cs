// Independent byte builder/decoder so oracle inputs do not depend on the BCL serializer.
using System.Buffers.Binary;
using System.Globalization;
using System.Text;

static class Sd
{
    public const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, SaclPresent = 0x0010,
        DaclProtected = 0x1000, DaclAutoInherited = 0x0400;
    public const byte Ci = 0x02, Oi = 0x01, Np = 0x04, Io = 0x08, Inherited = 0x10, Success = 0x40, Failure = 0x80;

    public static readonly byte[] Everyone = Sid("S-1-1-0");
    public static readonly byte[] Admins = Sid("S-1-5-32-544");
    public static readonly byte[] U1 = Sid("S-1-5-21-1-2-3-1001");
    public static readonly byte[] U2 = Sid("S-1-5-21-1-2-3-1002");
    public static readonly Guid G1 = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid G2 = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public static byte[] Sid(string text)
    {
        var parts = text.Split('-');
        var subs = parts.Skip(3).Select(p => uint.Parse(p, CultureInfo.InvariantCulture)).ToArray();
        var bytes = new byte[8 + 4 * subs.Length];
        bytes[0] = 1; bytes[1] = (byte)subs.Length;
        var authority = ulong.Parse(parts[2], CultureInfo.InvariantCulture);
        for (var i = 0; i < 6; i++) bytes[2 + i] = (byte)(authority >> ((5 - i) * 8));
        for (var i = 0; i < subs.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8 + 4 * i), subs[i]);
        return bytes;
    }

    /// <summary>Common ACE (types 0x00-0x03 and callback 0x09/0x0A share this prefix).</summary>
    public static byte[] Ace(byte type, byte flags, uint mask, byte[] sid, byte[]? tail = null)
    {
        tail ??= Array.Empty<byte>();
        var ace = new byte[8 + sid.Length + tail.Length];
        ace[0] = type; ace[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), mask);
        sid.CopyTo(ace, 8); tail.CopyTo(ace, 8 + sid.Length);
        return ace;
    }

    /// <summary>Object ACE (0x05-0x08, callback object 0x0B/0x0C). objectFlags written raw.</summary>
    public static byte[] ObjAce(byte type, byte flags, uint mask, uint objectFlags, Guid? objectType,
        Guid? inheritedType, byte[] sid, byte[]? tail = null)
    {
        tail ??= Array.Empty<byte>();
        var body = new List<byte>();
        var header = new byte[12];
        header[0] = type; header[1] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), mask);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), objectFlags);
        body.AddRange(header);
        if (objectType is { } o) body.AddRange(o.ToByteArray());
        if (inheritedType is { } i) body.AddRange(i.ToByteArray());
        body.AddRange(sid); body.AddRange(tail);
        var ace = body.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
        return ace;
    }

    public static byte[] Acl(byte revision, params byte[][] aces)
    {
        var size = 8 + aces.Sum(a => a.Length);
        var acl = new byte[size];
        acl[0] = revision;
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4), (ushort)aces.Length);
        var cursor = 8;
        foreach (var ace in aces) { ace.CopyTo(acl, cursor); cursor += ace.Length; }
        return acl;
    }

    /// <summary>
    /// Self-relative descriptor. Component order: owner, group, SACL, DACL. Present bits are
    /// derived from arguments unless <paramref name="control"/> overrides them; nullDacl writes
    /// DACL_PRESENT with offset 0.
    /// </summary>
    public static byte[] Build(byte[]? owner, byte[]? group, byte[]? dacl, byte[]? sacl = null,
        ushort extraControl = 0, bool nullDacl = false)
    {
        var control = (ushort)(SelfRelative | extraControl);
        if (dacl is not null || nullDacl) control |= DaclPresent;
        if (sacl is not null) control |= SaclPresent;
        var buffer = new List<byte>(new byte[20]);
        int Place(byte[]? part) { if (part is null) return 0; var at = buffer.Count; buffer.AddRange(part); return at; }
        var o = Place(owner); var g = Place(group); var s = Place(sacl); var d = Place(dacl);
        var sd = buffer.ToArray();
        sd[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(sd.AsSpan(2), control);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(4), (uint)o);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(8), (uint)g);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(12), (uint)s);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(16), (uint)d);
        return sd;
    }

    /// <summary>Raw ACE byte arrays of the DACL or SACL, in order; empty when the ACL is absent/NULL.</summary>
    public static List<byte[]> AceList(byte[] sd, bool sacl)
    {
        var result = new List<byte[]>();
        var control = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(2));
        if ((control & (sacl ? SaclPresent : DaclPresent)) == 0) return result;
        var offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(sacl ? 12 : 16));
        if (offset == 0) return result;
        var count = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(offset + 4));
        var cursor = offset + 8;
        for (var i = 0; i < count; i++)
        {
            var size = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(cursor + 2));
            result.Add(sd.AsSpan(cursor, size).ToArray());
            cursor += size;
        }
        return result;
    }

    public static string SidText(ReadOnlySpan<byte> b)
    {
        ulong authority = 0;
        for (var i = 0; i < 6; i++) authority = (authority << 8) | b[2 + i];
        var text = new StringBuilder($"S-{b[0]}-{authority}");
        for (var i = 0; i < b[1]; i++)
            text.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(b.Slice(8 + 4 * i)));
        return text.ToString();
    }

    static string Alias(string sid) => sid switch
    {
        "S-1-1-0" => "Everyone", "S-1-5-32-544" => "Admins",
        "S-1-5-21-1-2-3-1001" => "U1", "S-1-5-21-1-2-3-1002" => "U2", _ => sid,
    };

    static string GuidAlias(Guid g) => g == G1 ? "G1" : g == G2 ? "G2" : g == Guid.Empty ? "Zero" : g.ToString();

    static string AceTypeName(byte t) => t switch
    {
        0x00 => "Allow", 0x01 => "Deny", 0x02 => "Audit", 0x05 => "AllowObj", 0x06 => "DenyObj",
        0x07 => "AuditObj", 0x09 => "AllowCallback", 0x0A => "DenyCallback", 0x0B => "AllowCallbackObj",
        0x0C => "DenyCallbackObj", 0x11 => "MandatoryLabel", _ => $"Type0x{t:X2}",
    };

    public static string Describe(byte[] sd)
    {
        var text = new StringBuilder();
        if (sd.Length < 20) return $"<{sd.Length} bytes, too short>";
        var control = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(2));
        var offsets = new[] { 4, 8, 12, 16 }.Select(f => (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(f))).ToArray();
        text.Append($"len={sd.Length} ctrl=0x{control:X4} O@{offsets[0]} G@{offsets[1]} S@{offsets[2]} D@{offsets[3]}");
        if (offsets[0] != 0) text.Append($" owner={Alias(SidText(sd.AsSpan(offsets[0])))}");
        if (offsets[1] != 0) text.Append($" group={Alias(SidText(sd.AsSpan(offsets[1])))}");
        text.Append(" SACL=").Append(AclState(sd, control, SaclPresent, offsets[2]));
        text.Append(" DACL=").Append(AclState(sd, control, DaclPresent, offsets[3]));
        return text.ToString();
    }

    static string AclState(byte[] sd, ushort control, ushort presentBit, int offset)
    {
        if ((control & presentBit) == 0) return offset == 0 ? "absent" : $"absent(offset {offset})";
        if (offset == 0) return "NULL";
        var rev = sd[offset];
        var size = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(offset + 2));
        var count = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(offset + 4));
        var text = new StringBuilder($"rev{rev}/{count}[");
        var cursor = offset + 8;
        for (var i = 0; i < count && cursor + 4 <= offset + size; i++)
        {
            var type = sd[cursor]; var flags = sd[cursor + 1];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(sd.AsSpan(cursor + 2));
            var mask = BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(cursor + 4));
            if (i > 0) text.Append("; ");
            text.Append($"{AceTypeName(type)} f=0x{flags:X2} m=0x{mask:X}");
            var sidAt = cursor + 8;
            if (type is 0x05 or 0x06 or 0x07 or 0x08 or 0x0B or 0x0C)
            {
                var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(cursor + 8));
                sidAt = cursor + 12;
                text.Append($" of={objectFlags}");
                if ((objectFlags & 1) != 0) { text.Append($" ot={GuidAlias(new Guid(sd.AsSpan(sidAt, 16)))}"); sidAt += 16; }
                if ((objectFlags & 2) != 0) { text.Append($" it={GuidAlias(new Guid(sd.AsSpan(sidAt, 16)))}"); sidAt += 16; }
            }
            var sidLength = 8 + 4 * sd[sidAt + 1];
            text.Append($" {Alias(SidText(sd.AsSpan(sidAt)))}");
            var tail = cursor + aceSize - (sidAt + sidLength);
            if (tail != 0) text.Append($" tail={tail}");
            cursor += aceSize;
        }
        return text.Append(']').ToString();
    }
}
