#pragma warning disable CA1416 // Data-only shared enum values.
using System.Buffers.Binary;
using System.Security.AccessControl;

// Explicit binary fixtures: native outcomes are recorded separately, never predicted here.
internal static class SddlExportInputs
{
    internal sealed record Fixture(string Name, string Family, bool Dacl, byte[] Bytes, string? Text = null);
    internal sealed record Input(Fixture Fixture, string Operation, AccessControlSections Sections, string Prefix = "retained-export")
    { internal string Label => $"{Prefix}/{Fixture.Name}/{Operation}"; }

    internal static IEnumerable<Input> Create()
    {
        foreach (var fixture in Fixtures())
        {
            yield return new(fixture, "export-none", AccessControlSections.None);
            yield return new(fixture, "export-owner-group", AccessControlSections.Owner | AccessControlSections.Group);
            yield return new(fixture, "export-access", AccessControlSections.Access);
            yield return new(fixture, "export-audit", AccessControlSections.Audit);
            yield return new(fixture, "export-all", AccessControlSections.All);
            yield return new(fixture, "edit-owner", AccessControlSections.Owner);
            yield return new(fixture, "edit-group", AccessControlSections.Group);
            yield return new(fixture, "owner-then-export", fixture.Dacl ? AccessControlSections.Access : AccessControlSections.Audit);
        }
    }

    private static IEnumerable<Fixture> Fixtures()
    {
        // RA/FL ACE bytes are from the original mixed probe's valid SACL payloads.
        var ra = Convert.FromHexString("12005C0000000000010100000000000100000000180000000300000000000000020000002E000000400000004400650070006100720074006D0065006E00740000005200650073006500610072006300680000004F00700073000000");
        var fl = Convert.FromHexString("150034001000000001010000000000010000000061727478F90A0000004C006500760065006C0004020000000000000003028500");
        foreach (var (name, ace) in new[] { ("ML", Ace(17, 0, 1, sid: "010100000000001000100000")),
            ("RA", ra), ("SP", Ace(19, 0, 16)), ("TL", Ace(20, 0, 16)), ("FL", fl) })
        {
            yield return Make(name + "-SACL", "omitted-label-policy-resource-filter", false, ace);
            yield return Make(name + "-DACL", "wrong-section-special-ace", true, ace);
        }
        foreach (byte type in new byte[] { 0, 1, 5, 6, 9, 10, 11 })
            yield return Make($"access-audit-flags-{type}", "non-audit-ace-audit-flags", true, Ace(type, 64, 16));
        yield return Make("opaque-common", "noncallback-opaque", true, Ace(0, 0, 16, opaque: [1, 2, 3, 4]));
        yield return Make("opaque-zero-mask", "noncallback-opaque", true, Ace(0, 0, 0, opaque: [1, 2, 3, 4]));
        yield return Make("opaque-object", "noncallback-opaque", true, Ace(5, 0, 16, opaque: [1, 2, 3, 4]));
        yield return Make("condition-unknown", "unrepresentable-condition", true, Ace(9, 0, 16, opaque: [97, 114, 116, 120, 255, 0, 0, 0]));
        yield return Make("condition-zero-mask", "unrepresentable-condition", true, Ace(9, 0, 0, opaque: [97, 114, 116, 120, 255, 0, 0, 0]));
        yield return Make("unknown-object-flags", "unknown-object-flags", true, Ace(5, 0, 16, objectFlags: 4));
        yield return Make("unknown-DACL", "no-sddl-token-layout", true, [22, 0, 8, 0, 1, 2, 3, 4]);
        yield return Make("unknown-SACL", "no-sddl-token-layout", false, [22, 0, 8, 0, 1, 2, 3, 4]);
        yield return Make("inactive-audit", "reviewed-inactive-control", false, Ace(2, 8, 16));
        yield return Make("inactive-access", "reviewed-inactive-control", true, Ace(0, 8, 16));
        yield return Make("known-order", "reviewed-order-control", true, Ace(5, 0, 16), Ace(0, 0, 32));
        yield return Make("known-compaction", "reviewed-compaction-control", true, Ace(0, 0, 32), Ace(0, 0, 64));
        yield return Make("known-no-propagate", "reviewed-flags-control", true, Ace(0, 4, 32));
        yield return Make("unaudited-active", "missing-audit-flags", false, Ace(2, 0, 16));
        yield return Make("opaque-audit", "noncallback-opaque", false, Ace(2, 64, 16, opaque: [1, 2, 3, 4]));
        // Exercise native text import's preserved no-GUID ZA tail, not a guessed encoding.
        yield return new("ZA-inactive-tail", "unrepresentable-condition-tail", true, [],
            "O:S-1-5-18G:S-1-5-32-544D:(ZA;IO;RP;;;WD;(@User.A == 1))S:(AU;SA;RP;;;SY)");
        // Raw SDDL can represent these conditions. Facade removal must not silently
        // discard their payloads merely because mask/IO normalization removed an ACE.
        var condition = fl[20..];
        yield return Make("condition-inactive-valid", "projected-opaque-contributor", true, Ace(9, 8, 16, opaque: condition));
        yield return Make("condition-zero-valid", "projected-opaque-contributor", true, Ace(9, 0, 0, opaque: condition));
        yield return Make("audit-condition-zero-valid", "projected-opaque-contributor", false, Ace(13, 64, 0, opaque: condition));
        yield return Make("condition-active-valid", "retained-opaque-control", true, Ace(9, 0, 16, opaque: condition));
    }

    internal static Fixture Make(string name, string family, bool dacl, params byte[][] extras)
    {
        var access = new List<byte[]> { Ace(0, 0, 16) };
        var audit = new List<byte[]> { Ace(2, 64, 16) };
        (dacl ? access : audit).AddRange(extras);
        var owner = Convert.FromHexString("010100000000000512000000");
        var group = Convert.FromHexString("01020000000000052000000020020000");
        var sacl = Acl(audit); var da = Acl(access);
        var bytes = new byte[20 + owner.Length + group.Length + sacl.Length + da.Length];
        bytes[0] = 1; BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), 0x8014);
        var offset = 20;
        foreach (var (field, part) in new[] { (4, owner), (8, group), (12, sacl), (16, da) })
        { BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(field), offset); part.CopyTo(bytes, offset); offset += part.Length; }
        return new(name, family, dacl, bytes);
    }

    private static byte[] Acl(List<byte[]> aces)
    {
        var bytes = new byte[8 + aces.Sum(a => a.Length)]; bytes[0] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), checked((ushort)bytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), checked((ushort)aces.Count));
        var offset = 8; foreach (var ace in aces) { ace.CopyTo(bytes, offset); offset += ace.Length; }
        return bytes;
    }

    internal static byte[] Ace(byte type, byte flags, int mask, uint objectFlags = 0, byte[]? opaque = null, string sid = "010100000000000100000000")
    {
        var sidBytes = Convert.FromHexString(sid); var obj = type is 5 or 6 or 7 or 8 or 11 or 12 or 15 or 16;
        var objectLength = obj ? 4 + ((objectFlags & 1) != 0 ? 16 : 0) + ((objectFlags & 2) != 0 ? 16 : 0) : 0;
        var bytes = new byte[8 + objectLength + sidBytes.Length + (opaque?.Length ?? 0)];
        bytes[0] = type; bytes[1] = flags; BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), checked((ushort)bytes.Length));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), mask);
        if (obj)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), objectFlags);
            var offset = 12;
            if ((objectFlags & 1) != 0) { new Guid("11111111-2222-3333-4444-555555555555").ToByteArray().CopyTo(bytes, offset); offset += 16; }
            if ((objectFlags & 2) != 0) new Guid("66666666-7777-8888-9999-aaaaaaaaaaaa").ToByteArray().CopyTo(bytes, offset);
        }
        sidBytes.CopyTo(bytes, 8 + objectLength); opaque?.CopyTo(bytes, bytes.Length - opaque.Length);
        return bytes;
    }
}
