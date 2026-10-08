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
        foreach (var condition in new[]
        {
            "@User.A == #0102FF", "@User.A == #ABC", "@User.A == #", "@User.A == {1,2}",
            "@User.A == {1,\"x\"}", "@User.A == {}", "@User.A == {{1}}", "@User.A == SID(WD)",
            "@User.A == Title", "@User.A != -0", "@User.A == -0x10", "@User.A == +077",
            "@User.A == 18446744073709551615", "@User.A == 18446744073709551616", "@User.A == 08",
            "@User.A == +9223372036854775808", "@User.A == 1 == 1",
            "Exists @User.A", "Exists @Resource.A", "Not_Exists @Device.A",
            "Member_of SID(WD)", "Member_of {1}", "Member_of @User.A",
            "Device_Member_of SID(WD)", "Member_of_Any SID(WD)", "Device_Member_of_Any SID(WD)",
            "Not_Member_of SID(WD)", "Not_Device_Member_of SID(WD)",
            "Not_Member_of_Any SID(WD)", "Not_Device_Member_of_Any SID(WD)",
            "@User.A Not_Contains 1", "@User.A Not_Any_of 1", "@User.A contains 1",
            "!@User.A", "(@User.A)", "@User.A && @User.B", "Title", "@User.A%0022B == 1",
            "@User.A%0025B == 1", "@User.A%0000B == 1", "@User.A%FFFF == 1", "@User.A == \" x \""
        })
        {
            var text = $"D:(XA;;RP;;;WD;({condition}))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }
        foreach (var text in new[]
        {
            "S:(XA;;RP;;;WD;(@User.A == 1))", "D:(XU;SA;RP;;;WD;(@User.A == 1))",
            "S:(XU;;RP;;;WD;(@User.A == 1))", "D:(XA;SA;RP;;;WD;(@User.A == 1))",
            "D:(RA;;;;;WD;(\"Name\",TS,0,\"x\"))", "S:(RA;;RP;;;WD;(\"Name\",TS,0,\"x\"))",
            "S:(RA;;;;;BA;(\"Name\",TS,0,\"x\"))", "S:(RA;SA;;;;WD;(\"Name\",TS,0,\"x\"))",
            "S:(RA;;;;;WD;(\"Age\",TI,0,9223372036854775808))"
        })
        {
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlErrorDetails", new { Text = text }, () =>
            {
                try { _ = new RawSecurityDescriptor(text); return null; }
                catch (Exception exception) { return new { Type = exception.GetType().FullName, ParamName = (exception as ArgumentException)?.ParamName, NativeErrorCode = (exception as System.ComponentModel.Win32Exception)?.NativeErrorCode }; }
            });
        }

        // Unparenthesized negation must be calibrated independently of parenthesized controls.
        foreach (var condition in new[]
        {
            "!@User.Age == 1", "!@User.Title Contains \"Eng\"",
            "!@User.Age == 1 && @User.Level == 2", "!@User.Age == 1 || @User.Level == 2",
            "!@User.A && @User.B || @User.C", "!(@User.Age == 1)",
            "!(@User.Title Contains \"Eng\")", "!!@User.Age == 1",
            "!@User.Age != 1", "@User.Age == 1 && !@User.Level >= 2",
            "OctetStringType==#1#2#3##", "@User.A == #1#", "@User.A == ##", "@User.A == #g",
            "A-B == 1", "A_B == 1", "A.B == 1", "A/B == 1", "A:B == 1",
            "@User.A;B == 1", "@User.A-B == 1", "@User.A/B == 1", "@User.A:B == 1",
            "@User.A%003bB == 1", "@User.A%002dB == 1", "A%002dB == 1",
            "@User.A#B == 1", "A#B == 1", "@User.A?B == 1", "A?B == 1",
            "@User.A\\B == 1", "A\\B == 1", "@User.A$B == 1", "A$B == 1"
        })
        {
            var text = $"D:(XA;;RP;;;WD;({condition}))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }
        foreach (var text in new[]
        {
            "D:AI(XA;OICI;FA;;;WD;(OctetStringType==#1#2#3##))",
            "D:(ZA;;RP;;;WD;(@User.Age == 1))",
            "D:(ZA;;RP;00000000-0000-0000-0000-000000000000;;WD;(@User.Age == 1))",
            "D:(XA;;RP;;;WD;(@User.Age == 1))"
        })
        {
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }

        foreach (var character in "#$'*+-;?@[]\\^`{}~%:,./_é研发")
        foreach (var prefix in new[] { "", "@User." })
        {
            var text = $"D:(XA;;RP;;;WD;({prefix}A{character}B == 1))";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
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
