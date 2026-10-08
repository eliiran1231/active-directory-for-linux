using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

// In-memory codecs and caller-owned pointer buffers only; no lookup or access evaluation.
internal static class SddlPayloadContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        var conditions = new[]
        {
            "@User.Title == \"Engineer\"", "@User.Title != \"Engineer\"", "@Device.Name == \"laptop\"",
            "@Resource.Department == \"Engineering\"", "Title == \"Engineer\"", "@USER.Title==\"\"",
            "@User.Age == 0", "@User.Age >= 18", "@User.Age < -1", "@User.Age <= +42",
            "@User.Age > 0x10", "@User.Age == 077", "@User.Age == -9223372036854775808",
            "@User.Age == 9223372036854775807", "@User.Age == 9223372036854775808",
            "@User.Title == @Resource.Title", "(@User.Age >= 18) && (@User.Title == \"Engineer\")",
            "(@User.Age == 1) || (@User.Age == 2) && (@User.Age == 3)", "!(@User.Age == 0)",
            "Exists Title", "Not_Exists Title", "@User.Title Contains \"Eng\"",
            "@User.Title Any_of {\"Engineer\",\"Manager\"}", "Member_of {SID(S-1-1-0),SID(S-1-5-32-544)}",
            "@User.T%0020itle == \"研发\"", "@User.Title == \"a;b(c)\"", "@User.Title == \"a\\b\"",
            "@User.Title == \"a%0022b\"", "@User.Title ==", "@User.Title = \"x\"",
            "@User.Title == \"x\" garbage", "(@User.Title == \"x\"", "1 == 1", "@User.Title"
        };
        foreach (var condition in conditions)
        {
            var text = $"D:(XA;;RP;;;WD;({condition}))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }
        foreach (var prefix in new[] { "D:(XD;;WP;;;WD;", "D:(ZA;;RP;11111111-2222-3333-4444-555555555555;;WD;", "S:(XU;SA;RP;;;WD;", "S:(XA;;RP;;;WD;", "D:(XU;SA;RP;;;WD;" })
        {
            var text = prefix + "(@User.Age == 1))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }
        foreach (var data in new[]
        {
            "\"Department\",TS,0,\"Engineering\"", "\"Name\",TS,0,\"\"", "\"Name\",TS,0,\"one\",\"two\"",
            "\"研发\",TS,0x2,\"a;b(c)\"", "\"Name\",TS,0", "\"\",TS,0,\"x\"",
            "\"Age\",TI,0,-1,0,9223372036854775807,-9223372036854775808",
            "\"Age\",TU,0,0,18446744073709551615", "\"Age\",TI,0,0x10,077,+42",
            "\"Flag\",TB,0,0,1", "\"Flag\",TB,0,2", "\"Flag\",TB,0,-1",
            "\"Sid\",TD,0,WD,S-1-5-32-544", "\"Bytes\",TX,0,0102FF,00", "\"Bytes\",TX,0,ABC",
            "\"Name\",TS,0x10000,\"x\"", "\"Name\",TS,0x40,\"x\"", "\"Name\",TS,0xffffffff,\"x\"",
            "\"Name\",TS,0,\"a%0022b\"", "\"Na%0020me\",TS,0,\"x\"",
            "\"Age\",TI,0,9223372036854775808", "\"Age\",TU,0,-1", "\"Name\",ZZ,0,\"x\""
        })
        {
            var text = "S:(RA;;;;;WD;(" + data + "))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
        }
        foreach (var revision in new byte[] { 0, 1, 2, 255 })
        foreach (var count in new byte[] { 0, 1, 15, 16, 255 })
        foreach (var offset in new[] { 0, 3 })
        {
            var r = revision; var c = count; var o = offset;
            record("SidPointer", new { Revision = r, Count = c, Offset = o }, () => Pointer(r, c, o));
        }
    }
    private static object Snapshot(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        return new { Hex = Convert.ToHexString(bytes), Control = (int)descriptor.ControlFlags };
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
            var sid = new SecurityIdentifier(IntPtr.Add(memory, offset));
            var before = new byte[sid.BinaryLength]; sid.GetBinaryForm(before, 0);
            Marshal.Copy(new byte[bytes.Length], 0, memory, bytes.Length);
            var after = new byte[sid.BinaryLength]; sid.GetBinaryForm(after, 0);
            return new { sid.Value, Hex = Convert.ToHexString(after), Detached = before.SequenceEqual(after) };
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
}
