using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Principal;

// Actual detached Windows string/binary conversion only. No access checks, identity
// lookup, token changes, privilege changes, handles or directory operations.
internal static class AccessFilterContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        const string condition = "(@User.Age >= 18)";
        var texts = new List<string>();
        foreach (var section in new[] { "D", "S" })
        {
            foreach (var flags in new[] { "", "OI", "CI", "NP", "IO", "ID", "CR", "TP", "SA", "FA", "OICINPIOIDCRTP", "SATP", "TPFA", "ZZ", "tp" })
                texts.Add($"{section}:(FL;{flags};RP;;;WD;{condition})");
            foreach (var mask in new[] { "", "0", "0x1", "GA", "FA", "0xffffffff", "0x100000000", "-1", "NW", "ZZ" })
                texts.Add($"{section}:(FL;;{mask};;;WD;{condition})");
            foreach (var sid in new[] { "WD", "SY", "BA", "S-1-19-512-4096", "S-1-5-21-1-2-3-1001", "", "garbage", "S-1-5" })
                texts.Add($"{section}:(FL;;RP;;;{sid};{condition})");
            foreach (var tail in new[] { "", ";", ";()", ";(@User.Age)", ";(1 == 1)", ";(Exists Title)", ";(Member_of SID(WD))", ";(@User.Age ==)", ";(@User.Age = 1)", ";(@User.Age == 1)junk", ";(@User.Age == 1);extra", ";((@User.Age >= 18) && (@Device.Name == \"a;b(c)\"))", ";(@User.A == #0102FF)", ";(@User.A == {1,2})", ";(@User.A == 9223372036854775808)" })
                texts.Add($"{section}:(FL;;RP;;;WD{tail})");
            foreach (var guid in new[] { "00000000-0000-0000-0000-000000000000", "11111111-2222-3333-4444-555555555555", "bad" })
            {
                texts.Add($"{section}:(FL;;RP;{guid};;WD;{condition})");
                texts.Add($"{section}:(FL;;RP;;{guid};WD;{condition})");
            }
        }
        texts.AddRange(new[] { "S:PAI(FL;TP;RP;;;WD;(@User.Age >= 18))", "D:(A;;RP;;;WD)S:(FL;;RP;;;WD;(@User.Age >= 18))(AU;SA;RP;;;WD)", "S:(FL;;RP;;;WD;(@User.Age >= 18))(FL;TP;WP;;;SY;(@User.Age < 65))", "S:(fl;;RP;;;WD;(@User.Age >= 18))" });
        foreach (var text in texts)
        {
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
            record("SddlErrorDetails", new { Text = text }, () =>
            {
                try { _ = new RawSecurityDescriptor(text); return null; }
                catch (Exception ex) { return new { Type = ex.GetType().FullName, ParamName = (ex as ArgumentException)?.ParamName, NativeErrorCode = (ex as System.ComponentModel.Win32Exception)?.NativeErrorCode }; }
            });
        }
        // Build independent type-21 binary ACEs from a measured callback condition,
        // including malformed/unrecognized payloads. Native formatting is observed,
        // never assumed to preserve bytes just because parsing accepts a CustomAce.
        var callback = (CommonAce)new RawSecurityDescriptor("D:(XA;;RP;;;WD;" + condition + ")").DiscretionaryAcl![0];
        var valid = callback.GetOpaque()!;
        var payloads = new List<byte[]> { valid, Array.Empty<byte>(), new byte[4], new byte[] { 1, 2, 3, 4 }, "artx"u8.ToArray(), valid[..^4], valid.Concat(new byte[4]).ToArray(), valid.Concat(new byte[] { 1, 2, 3, 4 }).ToArray() };
        foreach (var position in new[] { 0, 4, 5, valid.Length - 1 })
        {
            var altered = (byte[])valid.Clone(); altered[position] = 0xff; payloads.Add(altered);
        }
        foreach (var system in new[] { false, true })
        {
            foreach (var flags in new byte[] { 0, 1, 2, 4, 8, 16, 32, 64, 128, 255 })
                Format(record, system, flags, 16, "S-1-1-0", valid, 15);
            foreach (var payload in payloads)
                Format(record, system, 0, 16, "S-1-1-0", payload, 15);
            foreach (var mask in new[] { 0, 1, -1, 0x10000000, 0x1f01ff, 0x01000000 })
                Format(record, system, 64, mask, "S-1-19-512-4096", valid, 15);
            foreach (var sections in new[] { 0, 1, 2, 4, 8, 15 })
                Format(record, system, 0, 16, "S-1-1-0", valid, sections);
        }
    }

    private static void Format(Action<string, object, Func<object?>> record, bool system, byte flags, int mask, string sidText, byte[] condition, int sections)
    {
        var sid = new SecurityIdentifier(sidText);
        var payload = new byte[4 + sid.BinaryLength + condition.Length];
        BinaryPrimitives.WriteInt32LittleEndian(payload, mask); sid.GetBinaryForm(payload, 4); condition.CopyTo(payload, 4 + sid.BinaryLength);
        var acl = new RawAcl(2, 1); acl.InsertAce(0, new CustomAce((AceType)21, (AceFlags)flags, payload));
        var raw = new RawSecurityDescriptor(system ? ControlFlags.SystemAclPresent : ControlFlags.DiscretionaryAclPresent, null, null, system ? acl : null, system ? null : acl);
        var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
        record("SddlFormat", new { Hex = Convert.ToHexString(bytes), Sections = sections }, () => raw.GetSddlForm((AccessControlSections)sections));
    }

    private static object Snapshot(RawSecurityDescriptor raw)
    {
        var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
        return new { Hex = Convert.ToHexString(bytes), Control = (int)raw.ControlFlags };
    }
}
