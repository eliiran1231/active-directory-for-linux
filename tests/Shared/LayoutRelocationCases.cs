#pragma warning disable CA1416
using System.Buffers.Binary;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.Tests.Shared;

internal static class LayoutRelocationCases
{
    internal static IEnumerable<object[]> Matrix()
    {
        foreach (var section in new[] { "owner", "group", "dacl", "sacl" })
        foreach (var grow in new[] { false, true })
        foreach (var gap in new[] { 3, 4 })
        foreach (var fill in new[] { 0, 0xA5 })
            yield return new object[] { section, grow, gap, fill };
    }

    internal static SecurityMasks Mask(string section) => section switch
    {
        "owner" => SecurityMasks.Owner, "group" => SecurityMasks.Group,
        "sacl" => SecurityMasks.Sacl, _ => SecurityMasks.Dacl,
    };

    // Independently assemble both complete images; never invoke the production rewriter.
    internal static byte[] Image(string section, bool grow, int gap, int fill, bool edited)
    {
        var initialSid = grow ? Everyone : U1;
        var finalSid = grow ? U1 : Everyone;
        var owner = section == "owner" && edited ? finalSid : initialSid;
        var group = section == "group" && edited ? finalSid : initialSid;
        var two = edited ? grow : !grow;
        var dacl = section == "dacl" && two ? Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 16, U2)) : Acl(4, Ace(0, 0, 16, U1));
        var sacl = section == "sacl" && two ? Acl(4, Ace(2, 64, 16, U1), Ace(2, 64, 16, U2)) : Acl(4, Ace(2, 64, 16, U1));
        var order = section is "dacl" or "sacl"
            ? new[] { section == "dacl" ? Part.Dacl : Part.Sacl, section == "dacl" ? Part.Sacl : Part.Dacl, Part.Owner, Part.Group }
            : new[] { Part.Owner, Part.Group, Part.Sacl, Part.Dacl };
        return PrefixGap(Build(owner, group, dacl, sacl, order: order), gap, fill);
    }

    internal static byte[] PrefixGap(byte[] packed, int gap, int fill)
    {
        var result = new byte[packed.Length + gap];
        packed.AsSpan(0, 20).CopyTo(result);
        result.AsSpan(20, gap).Fill((byte)fill);
        packed.AsSpan(20).CopyTo(result.AsSpan(20 + gap));
        foreach (var field in new[] { 4, 8, 12, 16 })
        {
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(packed.AsSpan(field));
            if (offset != 0) BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(field), offset + (uint)gap);
        }
        return result;
    }

    internal static void Edit(ActiveDirectorySecurity target, string section, bool grow)
    {
        var sid = new SecurityIdentifier(grow ? U1 : Everyone, 0);
        if (section == "owner") target.SetOwner(sid);
        else if (section == "group") target.SetGroup(sid);
        else if (section == "sacl")
        {
            var rule = new ActiveDirectoryAuditRule(new SecurityIdentifier(U2, 0), ActiveDirectoryRights.ReadProperty, AuditFlags.Success);
            if (grow) target.AddAuditRule(rule); else target.RemoveAuditRuleSpecific(rule);
        }
        else
        {
            var rule = new ActiveDirectoryAccessRule(new SecurityIdentifier(U2, 0), ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
            if (grow) target.AddAccessRule(rule); else target.RemoveAccessRuleSpecific(rule);
        }
    }
}
