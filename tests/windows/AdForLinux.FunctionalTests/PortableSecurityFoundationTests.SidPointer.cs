using System.Runtime.InteropServices;
using System.Text.Json;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static object ReplaySidPointer(JsonElement arguments)
    {
        return Pointer((byte)arguments.GetProperty("Revision").GetInt32(), (byte)arguments.GetProperty("Count").GetInt32(), arguments.GetProperty("Offset").GetInt32());
    }

    private static object Pointer(byte revision, byte count, int offset)
    {
        // Max indicated SID bytes fit the caller-owned allocation, even with invalid headers.
        var bytes = new byte[8 + 255 * 4 + offset];
        bytes[offset] = revision; bytes[offset + 1] = count; bytes[offset + 7] = 5;
        for (var i = 0; i < count; i++) System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 8 + i * 4), (uint)i);
        var memory = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, memory, bytes.Length);
            var sid = new AdForLinux.Security.Principal.SecurityIdentifier(IntPtr.Add(memory, offset));
            var before = new byte[sid.BinaryLength]; sid.GetBinaryForm(before, 0);
            Marshal.Copy(new byte[bytes.Length], 0, memory, bytes.Length);
            var after = new byte[sid.BinaryLength]; sid.GetBinaryForm(after, 0);
            return new { sid.Value, Hex = Convert.ToHexString(after), Detached = before.SequenceEqual(after) };
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
}
