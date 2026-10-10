using System.Security.AccessControl;
using System.Security.Principal;

// Detached native SDDL syntax/format observations, without descriptor persistence or evaluation.
internal static class SddlContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        var g = "11111111-2222-3333-4444-555555555555";
        var h = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        var texts = new List<string?>
        {
            null, "", "O:SY", "G:BA", "O:SYG:BAD:S:", "D:", "S:", "D:NO_ACCESS_CONTROL", "S:NO_ACCESS_CONTROL",
            "D:PNO_ACCESS_CONTROL", "D:PARAI", "D:AIPAR", "D:PAI(A;;RP;;;WD)", "S:PARAI(AU;SAFA;RP;;;WD)",
            "D:(A;;;;;WD)", "D:(A;;0;;;WD)", "D:(A;;16;;;WD)", "D:(A;;0X10;;;WD)", "D:(A;;-1;;;WD)",
            "D:(A;;0xffffffff;;;WD)", "D:(A;;0x100000000;;;WD)", "D:(A;;0x;;;WD)",
            "O:S-1-5-21-1-2-3-1001G:S-1-5-32-544D:(A;;RP;;;S-1-1-0)",
            "S:(AU;FA;WP;;;SY)D:(D;;WP;;;WD)(A;;RP;;;WD)G:BAO:SY",
            "D:(A;;RP;;;WD)(A;;WP;;;WD)", "D:(D;;WP;;;WD)(A;;RP;;;WD)",
            "d:(a;;rp;;;wd)", " D:(A;;RP;;;WD)", "D: (A;;RP;;;WD)", "D:(A; OI;RP;;;WD)",
            "D:(A;;RP;;;WD) ", "O:", "G:", "D:D:", "O:SYO:BA", "D:bogus", "D:(A;;RP;;;garbage)",
            "D:(XX;;RP;;;WD)", "D:(A;ZZ;RP;;;WD)", "D:(A;;ZZ;;;WD)", "D:(A;;RP;;;WD", "D:A;;RP;;;WD)",
            "D:(A;;RP;;;WD;extra)", "D:(A;;RP;;;)" ,"D:(A;;RP;bad;;WD)",
            $"D:(A;;RP;{g};;WD)", $"D:(OA;;RP;{{{g}}};;WD)",
            "D:(XA;;RP;;;WD)", "D:(XD;;WP;;;WD)", "S:(XU;SA;RP;;;WD)",
            "D:(XA;;RP;;;WD;(@User.Title == \"Engineer\"))",
            "S:(RA;;;;;WD;(\"Department\",TS,0,\"Engineering\"))",
            "S:(ML;;NW;;;LW)", "S:(SP;;0;;;S-1-17-1)", "S:(TL;;0;;;S-1-19-512-4096)",
            "D:(A;CR;RP;;;WD)", "D:(A;TP;RP;;;WD)"
        };
        foreach (var type in new[] { "A", "D", "AU", "AL", "OA", "OD", "OU", "OL", "ZA" })
        foreach (var shape in new[] { 0, 1, 2, 3, 4 })
            texts.Add($"D:({type};OICI;RP;{(shape is 1 or 3 ? g : shape == 4 ? Guid.Empty.ToString() : "")};{(shape is 2 or 3 ? h : "")};WD)");
        foreach (var rights in new[] { "GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO", "CC", "DC", "LC", "SW", "RP", "WP", "DT", "LO", "CR", "FA", "FR", "FW", "FX", "KA", "KR", "KW", "KX", "NR", "NW", "NX", "RPWPCCDCLCSWRCWDWOGA", "GRGWGXGA", "0x02000000", "0x01000000" })
            texts.Add($"D:(A;;{rights};;;WD)");
        foreach (var flags in new[] { "OI", "CI", "NP", "IO", "ID", "SA", "FA", "OICINPIOIDSAFA", "FAIDIOCINPOISA", "OIOI", "CR", "TP" })
            texts.Add($"D:(A;{flags};RP;;;WD)");
        // Documented Sddl.h token family, including domain-relative tokens whose native result
        // is evidence only; the portable codec must not infer ambient authority from this host.
        foreach (var alias in "AA AC AN AO AP AS AU BA BG BO BU CA CD CG CN CO CY DA DC DD DG DU EA ED EK ER ES HA HI HO IS IU KA LA LG LS LU LW ME MP MU NO NS NU OW PA PO PS PU RA RC RD RE RM RO RS RU SA SH SI SO SS SU SY UD WD WR".Split(' '))
        {
            texts.Add("O:" + alias);
            texts.Add("G:" + alias);
        }
        foreach (var text in texts)
        {
            if (text is "O:LA" or "G:LA" or "O:LG" or "G:LG")
                record("SddlHostRelative", new { Text = text }, () =>
                {
                    var descriptor = new RawSecurityDescriptor(text);
                    var identity = text[0] == 'O' ? descriptor.Owner! : descriptor.Group!;
                    var binary = new byte[identity.BinaryLength]; identity.GetBinaryForm(binary, 0);
                    var kind = text.EndsWith("LA", StringComparison.Ordinal)
                        ? WellKnownSidType.AccountAdministratorSid : WellKnownSidType.AccountGuestSid;
                    // The host-specific SID is intentionally not a portable expected value.
                    // Record only measured invariants, without guessing a local machine/domain.
                    return new
                    {
                        IsWellKnown = identity.IsWellKnown(kind),
                        Rid = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(binary.Length - 4)),
                        DomainPresent = identity.AccountDomainSid is not null,
                        CanonicalRoundTrip = descriptor.GetSddlForm(AccessControlSections.All),
                    };
                });
            else
                record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text!)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text!).GetSddlForm(AccessControlSections.All));
        }
        var sid = new SecurityIdentifier("S-1-1-0");
        var masks = Enumerable.Range(0, 32).Select(bit => unchecked(1 << bit)).Concat(new[] { 0, -1, 0x1ff, 0xf01ff, 0x1f01ff, 0x1f0003, 0x1f003f, 0x1f0001, 0x1f01ff, 0x1f01ff, 0x120089, 0x120116, 0x1200a0, 0xf003f, 0x20019, 0x20006, 0x00100000 });
        foreach (var mask in masks)
        {
            var acl = new RawAcl(2, 1);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, mask, sid, false, null));
            RecordFormat(record, new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, acl), 15);
        }
        foreach (var sections in new[] { -1, 0, 1, 2, 4, 8, 15, 16, 31 })
            RecordFormat(record, new RawSecurityDescriptor("O:SYG:BAD:PAI(A;;RP;;;WD)S:(AU;SA;WP;;;SY)"), sections);
        foreach (var type in new[] { 0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 255 })
        {
            byte[] bytes;
            if (type is >= 5 and <= 8 or 11 or 12 or 15 or 16)
            {
                var ace = new ObjectAce(AceFlags.None, AceQualifier.AccessAllowed, 16, sid, ObjectAceFlags.ObjectAceTypePresent, Guid.Parse(g), Guid.Empty, false, null);
                bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); bytes[0] = (byte)type;
            }
            else
            {
                var ace = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 16, sid, false, null);
                bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); bytes[0] = (byte)type;
            }
            var aclBytes = new byte[8 + bytes.Length]; aclBytes[0] = 4;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(aclBytes.AsSpan(2), (ushort)aclBytes.Length); aclBytes[4] = 1; bytes.CopyTo(aclBytes, 8);
            var acl = new RawAcl(aclBytes, 0);
            RecordFormat(record, new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, acl), 15);
        }
        foreach (var flags in new[] { 0, 1, 2, 4, 8, 16, 32, 64, 128, 255 })
        foreach (var opaque in new[] { "", "01020304", "6172747800000000" })
        {
            var acl = new RawAcl(2, 1);
            acl.InsertAce(0, new CommonAce((AceFlags)flags, AceQualifier.AccessAllowed, 16, sid, false, Convert.FromHexString(opaque)));
            RecordFormat(record, new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, acl), 15);
        }
        // Calibrate the valid audit families separately from the deliberately invalid no-audit-flag rows.
        foreach (var type in new[] { "AU", "AL", "OU", "OL" })
        foreach (var section in new[] { "D", "S" })
        foreach (var flags in new[] { "SA", "FA", "SAFA" })
        foreach (var objectGuid in new[] { "", g })
        {
            var text = $"{section}:({type};{flags};RP;{objectGuid};;WD)";
            record("SddlParse", new { Text = text }, () => Snapshot(new RawSecurityDescriptor(text)));
            record("SddlRoundTrip", new { Text = text, Sections = 15 }, () => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.All));
        }
        // Error details are operation outcomes, preserving the shared recorder schema.
        foreach (var text in new[] { "O:", "D:(XX;;RP;;;WD)", "D:(A;ZZ;RP;;;WD)", "D:(A;;RP;;;)",
            $"D:(OA;;RP;{{{g}}};;WD)", "D:(OU;;RP;;;WD)", "D:(AU;;RP;;;WD)", "D:(A;TP;RP;;;WD)" })
            record("SddlErrorDetails", new { Text = text }, () => {
                try { _ = new RawSecurityDescriptor(text); return null; }
                catch (Exception exception) { return new { Type = exception.GetType().FullName, ParamName = (exception as ArgumentException)?.ParamName,
                    NativeErrorCode = (exception as System.ComponentModel.Win32Exception)?.NativeErrorCode }; }
            });
    }

    private static object Snapshot(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        return new { Hex = Convert.ToHexString(bytes), Control = (int)descriptor.ControlFlags };
    }
    private static void RecordFormat(Action<string, object, Func<object?>> record, RawSecurityDescriptor descriptor, int sections)
    {
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        record("SddlFormat", new { Hex = Convert.ToHexString(bytes), Sections = sections }, () => descriptor.GetSddlForm((AccessControlSections)sections));
    }
}
