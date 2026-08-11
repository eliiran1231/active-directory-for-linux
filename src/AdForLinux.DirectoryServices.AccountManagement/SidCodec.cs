using System.Globalization;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Converts Windows security identifiers between SDDL and binary form.</summary>
internal static class SidCodec
{
    public static byte[] Parse(string value)
    {
        var parts = value.Split('-');
        if (parts.Length < 3
            || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)
            || !byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision)
            || revision != 1
            || parts.Length - 3 > 15)
        {
            throw new ArgumentException("The identity value is not a valid SID.", nameof(value));
        }

        var authorityText = parts[2];
        var authorityStyle = NumberStyles.None;
        if (authorityText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            authorityText = authorityText[2..];
            authorityStyle = NumberStyles.AllowHexSpecifier;
        }

        if (!ulong.TryParse(authorityText, authorityStyle, CultureInfo.InvariantCulture, out var authority)
            || authority > 0x0000FFFFFFFFFFFFUL)
        {
            throw new ArgumentException("The identity value is not a valid SID.", nameof(value));
        }

        var subAuthorityCount = parts.Length - 3;
        var bytes = new byte[8 + (subAuthorityCount * 4)];
        bytes[0] = revision;
        bytes[1] = (byte)subAuthorityCount;
        for (var index = 0; index < 6; index++)
        {
            bytes[2 + index] = (byte)(authority >> ((5 - index) * 8));
        }

        for (var index = 0; index < subAuthorityCount; index++)
        {
            if (!uint.TryParse(
                    parts[index + 3], NumberStyles.None, CultureInfo.InvariantCulture,
                    out var subAuthority))
            {
                throw new ArgumentException("The identity value is not a valid SID.", nameof(value));
            }

            var offset = 8 + (index * 4);
            bytes[offset] = (byte)subAuthority;
            bytes[offset + 1] = (byte)(subAuthority >> 8);
            bytes[offset + 2] = (byte)(subAuthority >> 16);
            bytes[offset + 3] = (byte)(subAuthority >> 24);
        }

        return bytes;
    }

    public static string Format(byte[] value)
    {
        if (value.Length < 8 || value[0] != 1 || value[1] > 15
            || value.Length < 8 + (value[1] * 4))
        {
            throw new ArgumentException("The directory value is not a valid SID.", nameof(value));
        }

        ulong authority = 0;
        for (var index = 0; index < 6; index++)
        {
            authority = (authority << 8) | value[2 + index];
        }

        var parts = new List<string>
        {
            "S",
            value[0].ToString(CultureInfo.InvariantCulture),
            authority.ToString(CultureInfo.InvariantCulture),
        };
        for (var index = 0; index < value[1]; index++)
        {
            var offset = 8 + (index * 4);
            var subAuthority = (uint)(value[offset]
                | (value[offset + 1] << 8)
                | (value[offset + 2] << 16)
                | (value[offset + 3] << 24));
            parts.Add(subAuthority.ToString(CultureInfo.InvariantCulture));
        }

        return string.Join('-', parts);
    }
}
