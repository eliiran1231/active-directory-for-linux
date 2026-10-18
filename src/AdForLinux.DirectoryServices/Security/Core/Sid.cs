using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace AdForLinux.DirectoryServices.Security.Core;

/// <summary>
/// An immutable Windows security identifier, held in its binary form. This is the portable
/// core value; it performs no name translation and has no BCL identity dependency.
/// </summary>
internal sealed class Sid : IEquatable<Sid>
{
    internal const int MinBinaryLength = 8;
    internal const int MaxSubAuthorities = 15;
    internal const int MaxBinaryLength = MinBinaryLength + (4 * MaxSubAuthorities);
    private const ulong MaxIdentifierAuthority = 0x0000FFFFFFFFFFFFUL;

    private readonly byte[] _value;

    private Sid(byte[] value)
    {
        _value = value;
    }

    /// <summary>Gets the number of bytes in the binary form.</summary>
    public int BinaryLength => _value.Length;

    /// <summary>Gets the 48-bit identifier authority, stored big-endian on the wire.</summary>
    public ulong IdentifierAuthority
    {
        get
        {
            ulong authority = 0;
            for (var index = 0; index < 6; index++)
            {
                authority = (authority << 8) | _value[2 + index];
            }

            return authority;
        }
    }

    public int SubAuthorityCount => _value[1];

    /// <summary>Gets one sub-authority, stored little-endian on the wire.</summary>
    public uint GetSubAuthority(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, SubAuthorityCount);
        return BinaryPrimitives.ReadUInt32LittleEndian(_value.AsSpan(8 + (4 * index)));
    }

    public ReadOnlySpan<byte> AsSpan() => _value;

    public byte[] ToArray() => _value.ToArray();

    public void WriteTo(Span<byte> destination) => _value.CopyTo(destination);

    /// <summary>
    /// Reads a SID from the start of <paramref name="source"/>. Bytes after the SID are not part
    /// of it; <paramref name="consumed"/> reports exactly how many bytes were used.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out Sid? sid, out int consumed)
    {
        sid = null;
        consumed = 0;
        if (source.Length < MinBinaryLength || source[0] != 1 || source[1] > MaxSubAuthorities)
        {
            return false;
        }

        var length = MinBinaryLength + (4 * source[1]);
        if (source.Length < length)
        {
            return false;
        }

        sid = new Sid(source[..length].ToArray());
        consumed = length;
        return true;
    }

    /// <summary>
    /// Parses the numeric <c>S-1-authority-sub...</c> form. The authority may be decimal or
    /// <c>0x</c>-prefixed hexadecimal; every other component is strict unsigned decimal.
    /// Aliases such as <c>BA</c> are not accepted.
    /// </summary>
    public static Sid Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var parts = value.Split('-');
        if (parts.Length < 3
            || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)
            || !byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision)
            || revision != 1
            || parts.Length - 3 > MaxSubAuthorities)
        {
            throw new ArgumentException("The value is not a valid SID.", nameof(value));
        }

        var authorityText = parts[2];
        var authorityStyle = NumberStyles.None;
        if (authorityText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            authorityText = authorityText[2..];
            authorityStyle = NumberStyles.AllowHexSpecifier;
        }

        if (!ulong.TryParse(authorityText, authorityStyle, CultureInfo.InvariantCulture, out var authority)
            || authority > MaxIdentifierAuthority)
        {
            throw new ArgumentException("The value is not a valid SID.", nameof(value));
        }

        var count = parts.Length - 3;
        var bytes = new byte[MinBinaryLength + (4 * count)];
        bytes[0] = revision;
        bytes[1] = (byte)count;
        for (var index = 0; index < 6; index++)
        {
            bytes[2 + index] = (byte)(authority >> ((5 - index) * 8));
        }

        for (var index = 0; index < count; index++)
        {
            if (!uint.TryParse(parts[index + 3], NumberStyles.None, CultureInfo.InvariantCulture, out var subAuthority))
            {
                throw new ArgumentException("The value is not a valid SID.", nameof(value));
            }

            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8 + (4 * index)), subAuthority);
        }

        return new Sid(bytes);
    }

    /// <summary>Formats as <c>S-1-authority-sub...</c> with unsigned decimal components.</summary>
    public override string ToString()
    {
        var text = new StringBuilder("S-1-");
        text.Append(IdentifierAuthority.ToString(CultureInfo.InvariantCulture));
        for (var index = 0; index < SubAuthorityCount; index++)
        {
            text.Append('-').Append(GetSubAuthority(index).ToString(CultureInfo.InvariantCulture));
        }

        return text.ToString();
    }

    public bool Equals(Sid? other) => other is not null && _value.AsSpan().SequenceEqual(other._value);

    public override bool Equals(object? obj) => Equals(obj as Sid);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_value);
        return hash.ToHashCode();
    }
}
