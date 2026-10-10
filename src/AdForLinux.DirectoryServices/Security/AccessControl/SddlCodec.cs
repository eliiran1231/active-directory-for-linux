#pragma warning disable CA1416 // Framework ACL enums are numeric values; this codec invokes no Windows APIs.
// Portable SDDL syntax/format implementation. Protocol references:
// https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
// https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
// Exact accepted forms and canonical output are replayed from detached Windows observations.
using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Security.AccessControl;
using System.Text;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

internal static class SddlCodec
{
    private static readonly (string Token, uint Bits)[] Rights =
    [
        ("CC", 1), ("DC", 2), ("LC", 4), ("SW", 8), ("RP", 16), ("WP", 32),
        ("DT", 64), ("LO", 128), ("CR", 256), ("SD", 0x10000), ("RC", 0x20000),
        ("WD", 0x40000), ("WO", 0x80000), ("GA", 0x10000000), ("GX", 0x20000000),
        ("GW", 0x40000000), ("GR", 0x80000000)
    ];
    private static readonly (string Token, uint Bits)[] CompositeRights =
    [
        ("FA", 0x1f01ff), ("FR", 0x120089), ("FW", 0x120116), ("FX", 0x1200a0),
        ("KA", 0xf003f), ("KR", 0x20019), ("KW", 0x20006), ("KX", 0x20019)
    ];
    private static readonly (string Token, byte Bits)[] AceFlagTokens =
    [ ("OI", 1), ("CI", 2), ("NP", 4), ("IO", 8), ("ID", 16), ("CR", 32), ("SA", 64), ("FA", 128) ];
    private static readonly Dictionary<string, byte> AceTypes = new(StringComparer.Ordinal)
    {
        ["A"] = 0, ["D"] = 1, ["AU"] = 2, ["AL"] = 3,
        ["OA"] = 5, ["OD"] = 6, ["OU"] = 7, ["OL"] = 8,
        ["XA"] = 9, ["XD"] = 10, ["ZA"] = 11, ["XU"] = 13,
        ["ML"] = 17, ["RA"] = 18, ["SP"] = 19, ["TL"] = 20
    };

    internal static byte[] Parse(string sddlForm)
    {
        ArgumentNullException.ThrowIfNull(sddlForm);
        var text = sddlForm.Trim();
        var fields = SplitDescriptor(text);
        SecurityIdentifier? owner = null, group = null;
        RawAcl? dacl = null, sacl = null;
        var control = ControlFlags.SelfRelative;
        foreach (var (kind, value) in fields)
        {
            switch (kind)
            {
                case 'O': owner = ParseSid(value); break;
                case 'G': group = ParseSid(value); break;
                case 'D': dacl = ParseAcl(value, false, ref control); break;
                case 'S': sacl = ParseAcl(value, true, ref control); break;
            }
        }
        var descriptor = new RawSecurityDescriptor(control, owner, group, sacl, dacl);
        var result = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(result, 0);
        return result;
    }

    private static List<(char Kind, string Value)> SplitDescriptor(string text)
    {
        var fields = new List<(char, string)>();
        var seen = new HashSet<char>();
        var i = 0;
        while (i < text.Length)
        {
            if (i + 1 >= text.Length || text[i + 1] != ':' || text[i] is not ('O' or 'G' or 'D' or 'S')) throw Invalid();
            var kind = text[i];
            if (!seen.Add(kind)) throw Invalid();
            var start = i += 2;
            var depth = 0; var quoted = false;
            while (i < text.Length)
            {
                var c = text[i];
                if (c == '"') quoted = !quoted;
                if (!quoted)
                {
                    if (c == '(') depth++;
                    else if (c == ')' && depth > 0) depth--;
                    if (depth == 0 && i + 1 < text.Length && text[i + 1] == ':' && c is 'O' or 'G' or 'D' or 'S') break;
                }
                i++;
            }
            if (depth != 0 || quoted) throw Invalid();
            fields.Add((kind, text[start..i].Trim()));
        }
        return fields;
    }

    private static SecurityIdentifier ParseSid(string text)
    {
        if (text.Length == 0) throw NativeInvalid(1332);
        if (text is "LA" or "LG") throw new NotSupportedException("Host-relative aliases require explicit machine SID authority.");
        try { return new SecurityIdentifier(text); }
        catch (ArgumentException) { throw Invalid(); }
    }

    private static RawAcl? ParseAcl(string text, bool system, ref ControlFlags control)
    {
        control |= system ? ControlFlags.SystemAclPresent : ControlFlags.DiscretionaryAclPresent;
        text = text.Trim();
        if (!text.Contains('(') && text.Contains(';')) text = "(" + text;
        var start = text.IndexOf('(');
        if (start < 0) start = text.Length;
        var flags = text[..start].Trim();
        var nullAcl = false;
        for (var i = 0; i < flags.Length;)
        {
            if (flags.AsSpan(i).StartsWith("NO_ACCESS_CONTROL", StringComparison.Ordinal)) { nullAcl = true; i += 17; }
            else if (flags[i] == 'P') { control |= system ? ControlFlags.SystemAclProtected : ControlFlags.DiscretionaryAclProtected; i++; }
            else if (flags.AsSpan(i).StartsWith("AR", StringComparison.Ordinal)) { control |= system ? ControlFlags.SystemAclAutoInheritRequired : ControlFlags.DiscretionaryAclAutoInheritRequired; i += 2; }
            else if (flags.AsSpan(i).StartsWith("AI", StringComparison.Ordinal)) { control |= system ? ControlFlags.SystemAclAutoInherited : ControlFlags.DiscretionaryAclAutoInherited; i += 2; }
            else throw Invalid();
        }
        if (nullAcl)
        {
            if (start != text.Length) throw new NotSupportedException("A NULL ACL combined with ACE text is not representable without discarding input.");
            return null;
        }
        var aces = new List<GenericAce>();
        var revision = (byte)2;
        while (start < text.Length)
        {
            if (text[start] != '(') throw Invalid();
            var end = AceEnd(text, start);
            var ace = ParseAce(text[(start + 1)..end], system);
            aces.Add(ace);
            if (ace is ObjectAce || text.AsSpan(start + 1).StartsWith("OA", StringComparison.Ordinal) || text.AsSpan(start + 1).StartsWith("OD", StringComparison.Ordinal) || text.AsSpan(start + 1).StartsWith("OU", StringComparison.Ordinal) || text.AsSpan(start + 1).StartsWith("ZA", StringComparison.Ordinal)) revision = 4;
            start = end + 1;
        }
        var acl = new RawAcl(revision, aces.Count);
        foreach (var ace in aces) acl.InsertAce(acl.Count, ace);
        return acl;
    }

    private static int AceEnd(string text, int start)
    {
        var depth = 0; var quoted = false;
        for (var i = start; i < text.Length; i++)
        {
            if (text[i] == '"') quoted = !quoted;
            if (quoted) continue;
            if (text[i] == '(') depth++;
            else if (text[i] == ')' && --depth == 0) return i;
        }
        throw Invalid();
    }

    private static GenericAce ParseAce(string text, bool system)
    {
        var fields = text.Split(';', 7).Select(field => field.Trim()).ToArray();
        if (fields.Length is not (6 or 7)) throw Invalid();
        // Native rejects FL in a DACL before examining flags, trustee or condition.
        if (fields[0].Equals("FL", StringComparison.OrdinalIgnoreCase))
        {
            if (!system) throw NativeInvalid(1804);
            return ParseAccessFilter(fields);
        }
        if (fields.Length == 7 && fields[0] is not ("XA" or "XD" or "XU" or "ZA" or "RA")) throw Invalid();
        if (!AceTypes.TryGetValue(fields[0], out var type))
        {
            throw NativeInvalid(1804);
        }
        if (!system && type is 7 or 8) throw NativeInvalid(1804);
        if (type is 3 or 8 || (!system && type == 2)) throw Invalid();
        if ((system && type is 9 or 10 or 11) || (!system && type is 13 or 18)) throw NativeInvalid(1804);
        var flags = ParseFlags(fields[1]);
        if (type is 9 or 10 or 11 or 13 or 18 && fields.Length != 7) throw Invalid();
        if (type is 2 or 3 && (flags & (AceFlags.SuccessfulAccess | AceFlags.FailedAccess)) == 0) throw Invalid();
        if (type is 7 or 8 && (flags & (AceFlags.SuccessfulAccess | AceFlags.FailedAccess)) == 0) throw NativeInvalid(1804);
        if (type is 0 or 1 or 5 or 6 or 9 or 10 or 11 or 18 && (flags & (AceFlags.SuccessfulAccess | AceFlags.FailedAccess)) != 0) throw NativeInvalid(1004);
        var mask = ParseRights(fields[2], type);
        var objectFlags = ObjectAceFlags.None;
        var objectType = Guid.Empty; var inheritedType = Guid.Empty;
        if (fields[3].Length != 0)
        {
            // ZA reports native GUID conversion errors before parsing its condition,
            // including when the eventual encoded ACE would exceed AceSize.
            if (!Guid.TryParseExact(fields[3], "D", out objectType)) { if (type == 11 || fields[3].StartsWith('{')) throw NativeInvalid(1705); throw Invalid(); }
            objectFlags |= ObjectAceFlags.ObjectAceTypePresent;
        }
        if (fields[4].Length != 0)
        {
            if (!Guid.TryParseExact(fields[4], "D", out inheritedType)) { if (type == 11) throw NativeInvalid(1705); throw Invalid(); }
            objectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
        }
        var sid = ParseSid(fields[5]);
        if (type == 18 && (mask != 0 || sid.Value != "S-1-1-0")) throw Invalid();
        var collapsedCallbackObject = type == 11 && objectFlags == 0;
        var isObject = type is >= 5 and <= 8 or 11;
        if (!isObject && objectFlags != 0)
            throw Invalid();
        if (isObject && objectFlags == 0) { type = type == 11 ? (byte)9 : (byte)(type - 5); isObject = false; }
        if (type >= 17)
        {
            var claim = type == 18 ? SddlResourceCodec.Parse(fields[6]) : Array.Empty<byte>();
            ValidateEncodedAceLength(8 + sid.BinaryLength + claim.Length);
            var payload = new byte[4 + sid.BinaryLength + claim.Length]; BinaryPrimitives.WriteInt32LittleEndian(payload, mask); sid.GetBinaryForm(payload, 4);
            claim.CopyTo(payload, 4 + sid.BinaryLength);
            return new CustomAce((AceType)type, flags, payload);
        }
        var qualifier = type switch
        {
            0 or 5 or 9 or 11 => AceQualifier.AccessAllowed,
            1 or 6 or 10 => AceQualifier.AccessDenied,
            2 or 7 or 13 => AceQualifier.SystemAudit,
            3 or 8 => AceQualifier.SystemAlarm,
            _ => throw Invalid()
        };
        var callback = type is 9 or 10 or 11 or 13;
        var opaque = callback ? SddlConditionCodec.Parse(fields[6]) : null;
        // Native no-GUID ZA conversion collapses the ACE but retains four zero bytes
        // in its opaque payload. Preserve them; text export must not silently omit them.
        if (collapsedCallbackObject) Array.Resize(ref opaque, opaque!.Length + 4);
        ValidateEncodedAceLength(8 + sid.BinaryLength + (opaque?.Length ?? 0)
            + (isObject ? 4 + ((objectFlags & ObjectAceFlags.ObjectAceTypePresent) != 0 ? 16 : 0)
                + ((objectFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0 ? 16 : 0) : 0));
        return isObject ? new ObjectAce(flags, qualifier, mask, sid, objectFlags, objectType, inheritedType, callback, opaque)
            : new CommonAce(flags, qualifier, mask, sid, callback, opaque);
    }

    private static CustomAce ParseAccessFilter(string[] fields)
    {
        if (fields.Length != 7) throw Invalid();
        var flagText = fields[1].ToUpperInvariant();
        if ((flagText.Length & 1) != 0) throw Invalid();
        byte flags = 0;
        for (var i = 0; i < flagText.Length; i += 2)
        {
            // TP shares bit 0x40 with audit success, but SA is invalid for FL.
            flags |= flagText.Substring(i, 2) switch
            {
                "OI" => (byte)1, "CI" => (byte)2, "NP" => (byte)4,
                "IO" => (byte)8, "ID" => (byte)16, "TP" => (byte)64,
                _ => throw NativeInvalid(1004)
            };
        }
        var mask = ParseRights(fields[2], 21);
        if ((unchecked((uint)mask) & 0xff000000u) != 0 || fields[3].Length != 0 || fields[4].Length != 0 || fields[5].Length == 0)
            throw Invalid();
        var sid = ParseSid(fields[5]);
        var sidBytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(sidBytes, 0);
        if ((flags & 64) == 0)
        {
            if (sid.Value != "S-1-1-0") throw Invalid();
        }
        else
        {
            // Measured native trust-filter shape: authority 19, exactly two RIDs.
            // A zero first RID requires a zero second RID; nonzero values are not
            // limited to named trust levels (including UINT_MAX in the oracle).
            if (sidBytes.Length != 16 || !sid.Value.StartsWith("S-1-19-", StringComparison.Ordinal)
                || (BinaryPrimitives.ReadUInt32LittleEndian(sidBytes.AsSpan(8)) == 0
                    && BinaryPrimitives.ReadUInt32LittleEndian(sidBytes.AsSpan(12)) != 0)) throw Invalid();
        }
        var condition = SddlConditionCodec.Parse(fields[6]);
        ValidateEncodedAceLength(8 + sidBytes.Length + condition.Length);
        var payload = new byte[4 + sidBytes.Length + condition.Length];
        BinaryPrimitives.WriteInt32LittleEndian(payload, mask);
        sidBytes.CopyTo(payload, 4); condition.CopyTo(payload, 4 + sidBytes.Length);
        return new CustomAce((AceType)21, (AceFlags)flags, payload);
    }

    private static void ValidateEncodedAceLength(int length)
    {
        // AceSize is a USHORT. The isolated Windows conversions reject an ACE
        // that cannot fit that field as ArgumentException(sddlForm), before any
        // managed ACE constructor sees it. Keep that import boundary separate
        // from the public constructors' opaque-array argument validation.
        // This is not an ACL capacity rule: representable ACEs have additional,
        // context-sensitive native conversion limits still under investigation.
        if (length > ushort.MaxValue) throw Invalid();
    }

    private static AceFlags ParseFlags(string text)
    {
        byte flags = 0;
        if ((text.Length & 1) != 0) throw Invalid();
        for (var i = 0; i < text.Length; i += 2)
        {
            var token = text.Substring(i, 2);
            var found = false;
            foreach (var pair in AceFlagTokens) if (pair.Token == token) { flags |= pair.Bits; found = true; break; }
            if (!found) throw NativeInvalid(1004);
        }
        return (AceFlags)flags;
    }

    private static int ParseRights(string text, byte type)
    {
        if (text.Length == 0) return 0;
        if (char.IsAsciiDigit(text[0]) || text[0] is '-' or '+')
        {
            var negative = text[0] == '-';
            var start = text[0] is '-' or '+' ? 1 : 0;
            var radix = 10u;
            if (text.AsSpan(start).StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { radix = 16; start += 2; }
            if (start == text.Length) throw Invalid();
            uint value = 0; var overflow = false;
            for (var i = start; i < text.Length; i++)
            {
                var c = text[i];
                var digit = c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'f' ? c - 'a' + 10 : c is >= 'A' and <= 'F' ? c - 'A' + 10 : -1;
                if (digit < 0 || digit >= radix) throw Invalid();
                if (overflow || value > (uint.MaxValue - (uint)digit) / radix) { value = uint.MaxValue; overflow = true; }
                else value = value * radix + (uint)digit;
            }
            return unchecked((int)(negative && !overflow ? 0u - value : value));
        }
        if ((text.Length & 1) != 0) throw Invalid();
        uint result = 0;
        for (var i = 0; i < text.Length; i += 2)
        {
            var token = text.Substring(i, 2);
            var match = Rights.Concat(CompositeRights).FirstOrDefault(p => p.Token == token);
            if (match.Token is null)
                match = (type, token) switch { (17, "NW") => (token, 1u), (17, "NR") => (token, 2u), (17, "NX") => (token, 4u), _ => throw Invalid() };
            result |= match.Bits;
        }
        return unchecked((int)result);
    }

    internal static string Format(GenericSecurityDescriptor descriptor, AccessControlSections sections)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        // Common ACL projection can hide RA/FL ACEs before AppendAce sees them.
        // Apply the existing loss refusal to the selected retained SACL too; live
        // ordering/compaction remains the observable output for supported ACEs.
        if ((sections & AccessControlSections.Audit) != 0 && descriptor is CommonSecurityDescriptor common
            && common.MutationState.Descriptor.Sacl is { } retainedSacl
            && retainedSacl.Aces.Any(ace => ace.AceType is 18 or 21))
            throw new NotSupportedException("Native SDDL export omits resource attributes or access filters; portable export refuses that information loss.");
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        var raw = new RawSecurityDescriptor(bytes, 0);
        var result = new StringBuilder();
        if ((sections & AccessControlSections.Owner) != 0 && raw.Owner is not null) result.Append("O:").Append(FormatSid(raw.Owner));
        if ((sections & AccessControlSections.Group) != 0 && raw.Group is not null) result.Append("G:").Append(FormatSid(raw.Group));
        if ((sections & AccessControlSections.Access) != 0 && (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0)
            AppendAcl(result, raw.DiscretionaryAcl, false, raw.ControlFlags);
        if ((sections & AccessControlSections.Audit) != 0 && (raw.ControlFlags & ControlFlags.SystemAclPresent) != 0)
            AppendAcl(result, raw.SystemAcl, true, raw.ControlFlags);
        return result.ToString();
    }

    private static string FormatSid(SecurityIdentifier sid) => SecurityIdentifier.GetSddlAlias(sid) ?? sid.Value;
    private static void AppendAcl(StringBuilder result, RawAcl? acl, bool system, ControlFlags flags)
    {
        result.Append(system ? "S:" : "D:");
        if ((flags & (system ? ControlFlags.SystemAclProtected : ControlFlags.DiscretionaryAclProtected)) != 0) result.Append('P');
        if ((flags & (system ? ControlFlags.SystemAclAutoInheritRequired : ControlFlags.DiscretionaryAclAutoInheritRequired)) != 0) result.Append("AR");
        if ((flags & (system ? ControlFlags.SystemAclAutoInherited : ControlFlags.DiscretionaryAclAutoInherited)) != 0) result.Append("AI");
        if (acl is null) { result.Append("NO_ACCESS_CONTROL"); return; }
        for (var i = 0; i < acl.Count; i++) AppendAce(result, acl[i], system);
    }

    private static void AppendAce(StringBuilder result, GenericAce ace, bool system)
    {
        var type = (byte)ace.AceType;
        if (type == 21)
        {
            if (!system) throw new InvalidOperationException("Access filters cannot be formatted in a DACL.");
            // GetSddlForm's ordinary Audit/All selection omits the whole native FL
            // ACE, including unknown or malformed payloads. Never imitate that loss.
            throw new NotSupportedException("Native SDDL export omits access filters; portable export refuses that information loss.");
        }
        if (type == 18 && !system) throw new InvalidOperationException("Resource attributes cannot be formatted in a DACL.");
        if (type == 18) throw new NotSupportedException("Native SDDL export omits resource attributes; portable export refuses that information loss.");
        var token = AceTypes.FirstOrDefault(pair => pair.Value == type).Key;
        if (token is null) throw new InvalidOperationException($"ACE type {type} has no valid SDDL representation.");
        if (type is 2 or 3 or 7 or 8 or 13 && (ace.AceFlags & (AceFlags.SuccessfulAccess | AceFlags.FailedAccess)) == 0)
            throw new InvalidOperationException("An audit/alarm ACE requires audit flags for SDDL output.");
        if (type is 17 or 19 or 20)
        {
            if (!system) throw new InvalidOperationException("Label and policy ACEs cannot be formatted in a DACL.");
            throw new NotSupportedException("Native SDDL output omits label/policy ACEs; portable export refuses that information loss.");
        }
        if (type is 0 or 1 or 5 or 6 or 9 or 10 or 11 && (ace.AceFlags & (AceFlags.SuccessfulAccess | AceFlags.FailedAccess)) != 0)
            throw new NotSupportedException("Native SDDL output omits non-audit ACE audit flags; portable export refuses that information loss.");
        string? condition = null;
        int mask; SecurityIdentifier sid; var objectType = ""; var inheritedType = "";
        if (ace is QualifiedAce qualified)
        {
            if (qualified.OpaqueLength != 0)
            {
                if (type is not (9 or 10 or 11 or 13)) throw new NotSupportedException("ACE opaque bytes cannot be omitted from SDDL.");
                condition = SddlConditionCodec.Format(qualified.GetOpaque()!);
            }
            mask = qualified.AccessMask; sid = qualified.SecurityIdentifier;
            if (ace is ObjectAce obj)
            {
                if ((obj.ObjectAceFlags & ~(ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent)) != 0)
                    throw new NotSupportedException("Unknown object ACE flags cannot be omitted from SDDL.");
                if ((obj.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0) objectType = obj.ObjectAceType.ToString("D");
                if ((obj.ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0) inheritedType = obj.InheritedObjectAceType.ToString("D");
            }
        }
        else if (ace is CustomAce custom && type is 17 or 19 or 20)
        {
            var payload = custom.GetOpaque();
            if (payload is null || payload.Length < 12) throw new NotSupportedException("The label ACE payload is not a complete mask and SID.");
            mask = BinaryPrimitives.ReadInt32LittleEndian(payload);
            sid = new SecurityIdentifier(payload, 4);
            if (payload.Length != 4 + sid.BinaryLength) throw new NotSupportedException("Unexplained label ACE trailing bytes cannot be omitted from SDDL.");
        }
        else throw new NotSupportedException("This ACE layout is not supported by SDDL.");
        result.Append('(').Append(token).Append(';');
        foreach (var flag in AceFlagTokens) if (((byte)ace.AceFlags & flag.Bits) != 0) result.Append(flag.Token);
        result.Append(';').Append(FormatRights(unchecked((uint)mask), type)).Append(';').Append(objectType).Append(';').Append(inheritedType).Append(';').Append(FormatSid(sid));
        if (condition is not null) result.Append(';').Append(condition);
        result.Append(')');
    }

    private static string FormatRights(uint mask, byte type)
    {
        if (mask == 0) return "";
        if (type == 17 && (mask & ~7u) == 0)
            return ((mask & 1) != 0 ? "NW" : "") + ((mask & 2) != 0 ? "NR" : "") + ((mask & 4) != 0 ? "NX" : "");
        foreach (var pair in CompositeRights) if (pair.Bits == mask) return pair.Token;
        var known = Rights.Aggregate(0u, (bits, p) => bits | p.Bits);
        if ((mask & ~known) != 0) return "0x" + mask.ToString("x", CultureInfo.InvariantCulture);
        var result = new StringBuilder();
        foreach (var pair in Rights) if ((mask & pair.Bits) != 0) result.Append(pair.Token);
        return result.ToString();
    }

    private static Win32Exception NativeInvalid(int errorCode) => new(errorCode);
    private static ArgumentException Invalid() => new("The SDDL text is invalid.", "sddlForm");
}
