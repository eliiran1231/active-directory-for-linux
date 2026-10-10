using System.Buffers.Binary;

namespace AdForLinux.Security.AccessControl;

// SDDL's native UTF-16 representation preserves code units, including unpaired
// surrogates. Encoding.Unicode's replacement fallback changes those input bytes.
internal static class SddlUtf16
{
    internal static byte[] Encode(string text)
    {
        var bytes = new byte[checked(text.Length * 2)];
        for (var i = 0; i < text.Length; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(i * 2), text[i]);
        return bytes;
    }

    internal static string Decode(byte[] bytes)
    {
        if ((bytes.Length & 1) != 0) throw new ArgumentException("Incomplete UTF-16 code unit.", nameof(bytes));
        return string.Create(bytes.Length / 2, bytes, (text, source) =>
        {
            for (var i = 0; i < text.Length; i++)
                text[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(source.AsSpan(i * 2));
        });
    }
}
