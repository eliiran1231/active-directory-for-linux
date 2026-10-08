// MS-DTYP 2.4.10.1 CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, calibrated with native recordings.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
using System.Buffers.Binary;
using System.ComponentModel;
using System.Text;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

internal static class SddlResourceCodec
{
    internal static byte[] Parse(string text)
    {
        if (text.Length < 2 || text[0] != '(' || text[^1] != ')') throw Invalid();
        var fields = new List<string>();
        var start = 1; var quoted = false;
        for (var i = 1; i < text.Length - 1; i++)
        {
            if (text[i] == '"') quoted = !quoted;
            if (text[i] != ',' || quoted) continue;
            fields.Add(text[start..i].Trim()); start = i + 1;
        }
        if (quoted) throw Invalid();
        fields.Add(text[start..^1].Trim());
        if (fields.Count < 4) throw Invalid();
        var name = SddlConditionCodec.UnescapeName(StringValue(fields[0]));
        if (name.Length == 0) throw Invalid();
        ushort type = fields[1] switch { "TI" => 1, "TU" => 2, "TS" => 3, "TD" => 5, "TB" => 6, "TX" => 16, _ => throw Invalid() };
        var flags = Number(fields[2]);
        if (flags > uint.MaxValue || (flags & 0x0000ffc0) != 0) throw Invalid();
        var values = fields.Skip(3).Select(value => Encode(type, value)).ToArray();
        var nameBytes = Encoding.Unicode.GetBytes(name + '\0');
        var headerLength = 16 + 4 * values.Length;
        var length = headerLength + nameBytes.Length + values.Sum(value => value.Length);
        var bytes = new byte[(length + 3) & ~3];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, headerLength);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), type);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), (uint)flags);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12), values.Length);
        nameBytes.CopyTo(bytes, headerLength);
        var position = headerLength + nameBytes.Length;
        for (var i = 0; i < values.Length; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16 + 4 * i), position);
            values[i].CopyTo(bytes, position); position += values[i].Length;
        }
        return bytes;
    }

    private static byte[] Encode(ushort type, string value)
    {
        if (type == 3) return Encoding.Unicode.GetBytes(StringValue(value) + '\0');
        if (type is 5 or 16)
        {
            byte[] data;
            if (type == 5)
            {
                if (value is "LA" or "LG") throw new NotSupportedException("Resource SID requires explicit host authority.");
                SecurityIdentifier sid;
                try { sid = new SecurityIdentifier(value); } catch (ArgumentException) { throw Invalid(); }
                data = new byte[sid.BinaryLength]; sid.GetBinaryForm(data, 0);
            }
            else
            {
                try { data = Convert.FromHexString((value.Length % 2 == 0 ? "" : "0") + value); }
                catch (FormatException) { throw Invalid(); }
            }
            var result = new byte[4 + data.Length]; BinaryPrimitives.WriteInt32LittleEndian(result, data.Length); data.CopyTo(result, 4); return result;
        }
        var number = Number(value);
        if (type == 6 && number > 1) throw Invalid();
        if (type == 1 && ((!value.StartsWith('-') && number > long.MaxValue) || (value.StartsWith('-') && unchecked(0UL - number) > 0x8000000000000000UL)))
            throw new Win32Exception(534);
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(bytes, number); return bytes;
    }

    private static string StringValue(string value)
    {
        if (value.Length < 2 || value[0] != '"' || value[^1] != '"' || value.AsSpan(1, value.Length - 2).Contains('"') || value.Contains('\0')) throw Invalid();
        return value[1..^1];
    }

    internal static ulong Number(string text)
    {
        var sign = text.StartsWith('-') ? -1 : 1;
        var start = text.Length > 0 && text[0] is '-' or '+' ? 1 : 0;
        var radix = 10;
        if (text.AsSpan(start).StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { radix = 16; start += 2; }
        else if (start < text.Length && text[start] == '0') radix = 8;
        if (start == text.Length) throw Invalid();
        ulong value = 0;
        for (var i = start; i < text.Length; i++)
        {
            var digit = text[i] is >= '0' and <= '9' ? text[i] - '0' : text[i] is >= 'a' and <= 'f' ? text[i] - 'a' + 10 : text[i] is >= 'A' and <= 'F' ? text[i] - 'A' + 10 : -1;
            if (digit < 0 || digit >= radix || value > (ulong.MaxValue - (uint)digit) / (uint)radix) throw Invalid();
            value = value * (uint)radix + (uint)digit;
        }
        return sign < 0 ? unchecked(0UL - value) : value;
    }
    private static ArgumentException Invalid() => new("The SDDL resource attribute is invalid.", "sddlForm");
}
