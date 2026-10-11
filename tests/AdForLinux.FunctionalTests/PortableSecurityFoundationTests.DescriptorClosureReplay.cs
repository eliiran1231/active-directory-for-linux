#pragma warning disable CA1416 // Framework enum values only.
using System.Text.Json;
namespace AdForLinux.FunctionalTests;
using System.Security.AccessControl;
using SystemAcl = AdForLinux.Security.AccessControl.SystemAcl;
using DiscretionaryAcl = AdForLinux.Security.AccessControl.DiscretionaryAcl;
using CommonAce = AdForLinux.Security.AccessControl.CommonAce;
using RawAcl = AdForLinux.Security.AccessControl.RawAcl;
using GenericAcl = AdForLinux.Security.AccessControl.GenericAcl;
using CommonSecurityDescriptor = AdForLinux.Security.AccessControl.CommonSecurityDescriptor;
using RawSecurityDescriptor = AdForLinux.Security.AccessControl.RawSecurityDescriptor;
using GenericSecurityDescriptor = AdForLinux.Security.AccessControl.GenericSecurityDescriptor;
using AdForLinux.Security.Principal;
using AdForLinux.Security.AccessControl;

internal static class PortableDescriptorClosureDriver
{
    internal static object? Execute(string operation, int scenario)
    {
        switch (operation)
        {
            case "DescriptorRaw":
                var flags = new[] { 0, 4, 16, 20, 65535 }[scenario / 9];
                var identities = scenario / 3 % 3;
                var aclMode = scenario % 3;
                var raw = new RawSecurityDescriptor((ControlFlags)flags, identities > 0 ? Sid(1) : null,
                    identities > 1 ? Sid(2) : null, MakeAcl(true, aclMode), MakeAcl(false, aclMode));
                raw.ResourceManagerControl = 0x5a;
                return Snapshot(raw);
            case "DescriptorBinary":
                var input = Bytes(new RawSecurityDescriptor((ControlFlags)20, Sid(1), Sid(2), MakeAcl(true, 2), MakeAcl(false, 2)));
                var offset = 0;
                switch (scenario)
                {
                    case 0: break;
                    case 1: input[0] = 2; break;
                    case 2: input[3] &= 0x7f; break;
                    case 3: input[2] &= 0xfb; break;
                    case 4: input.AsSpan(4, 4).CopyTo(input.AsSpan(8, 4)); break;
                    case 5: input.AsSpan(12, 4).CopyTo(input.AsSpan(16, 4)); break;
                    case 6: input[1] = 0x5a; break;
                    case 7: input[1] = 0x5a; input[3] |= 0x40; break;
                    case 8: input = input.Concat(new byte[] { 0xde, 0xad }).ToArray(); break;
                    case 9: offset = -1; break;
                    case 10: input = new byte[19]; break;
                    case 11: offset = 3; input = new byte[3].Concat(input).ToArray(); break;
                    case 12: input = null!; break;
                    case 13: input[4] = 0xff; input[5] = 0xff; input[6] = 0xff; input[7] = 0x7f; break;
                }
                return Snapshot(new RawSecurityDescriptor(input, offset));
            case "DescriptorCommon":
                var container = (scenario & 1) != 0;
                var ds = (scenario & 2) != 0;
                var mode = scenario / 4;
                var source = new RawSecurityDescriptor((ControlFlags)(mode == 0 ? 0 : 20), Sid(1), Sid(2),
                    mode >= 3 ? MakeAcl(true, mode == 4 ? 2 : 1) : null,
                    mode >= 2 ? MakeAcl(false, mode == 4 ? 2 : 1) : null);
                return Snapshot(new CommonSecurityDescriptor(container, ds, source));
            case "DescriptorProtection":
                var common = Common();
                var audit = (scenario & 1) != 0;
                var protect = (scenario & 2) != 0;
                var preserve = (scenario & 4) != 0;
                if ((scenario & 8) != 0) common.DiscretionaryAcl = null;
                if (audit) common.SetSystemAclProtection(protect, preserve);
                else common.SetDiscretionaryAclProtection(protect, preserve);
                return Snapshot(common);
            case "DescriptorSharing":
                var original = new RawSecurityDescriptor((ControlFlags)20, Sid(1), Sid(2), MakeAcl(true, 2), MakeAcl(false, 2));
                var detached = new CommonSecurityDescriptor(true, true, original);
                if (scenario == 0) original.DiscretionaryAcl!.RemoveAce(0);
                if (scenario == 1) detached.DiscretionaryAcl!.Purge(Sid(1));
                if (scenario == 2) original.Owner = Sid(3);
                if (scenario == 3) detached.Owner = Sid(3);
                if (scenario == 4) detached.SystemAcl = null;
                return new { Raw = Snapshot(original), Common = Snapshot(detached) };
            case "DescriptorWrite":
                var descriptor = Common();
                var length = scenario == 2 ? descriptor.BinaryLength - 1 : descriptor.BinaryLength + 4;
                var destination = scenario == 3 ? null! : Enumerable.Repeat((byte)0xcc, length).ToArray();
                var writeOffset = scenario switch { 1 => -1, 4 => 4, 5 => int.MaxValue, 6 => descriptor.BinaryLength + 4, _ => 0 };
                descriptor.GetBinaryForm(destination, writeOffset);
                return Convert.ToHexString(destination);
            case "DescriptorPurge":
                var purge = Common();
                if (scenario < 2) purge.PurgeAccessControl(scenario == 0 ? Sid(1) : null!);
                else purge.PurgeAudit(scenario == 2 ? Sid(1) : null!);
                return Snapshot(purge);
            case "DescriptorAclAssignment":
                var assignment = Common();
                if (scenario < 4) assignment.DiscretionaryAcl = scenario == 0 ? null
                    : new DiscretionaryAcl(scenario != 1, scenario != 2, 4);
                else assignment.SystemAcl = scenario == 4 ? null
                    : new SystemAcl(scenario != 5, scenario != 6, 4);
                return Snapshot(assignment);
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static SecurityIdentifier Sid(int id) => new($"S-1-5-21-1-2-3-{1000 + id}");
    private static RawAcl? MakeAcl(bool audit, int mode)
    {
        if (mode == 0) return null;
        var acl = new RawAcl(4, 2);
        if (mode == 2)
        {
            var flags = audit ? AceFlags.SuccessfulAccess : AceFlags.None;
            var qualifier = audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed;
            acl.InsertAce(0, new CommonAce(flags, qualifier, 16, Sid(1), false, null));
            acl.InsertAce(1, new CommonAce(flags | AceFlags.Inherited | AceFlags.ContainerInherit,
                qualifier, 32, Sid(2), false, null));
        }
        return acl;
    }
    private static CommonSecurityDescriptor Common() => new(true, true,
        new RawSecurityDescriptor((ControlFlags)20, Sid(1), Sid(2), MakeAcl(true, 2), MakeAcl(false, 2)));
    private static byte[] Bytes(GenericSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
    private static string? AclHex(GenericAcl? acl)
    {
        if (acl is null) return null;
        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return Convert.ToHexString(bytes);
    }
    private static object Snapshot(GenericSecurityDescriptor descriptor) => new
    {
        Type = descriptor.GetType().Name, Flags = (int)descriptor.ControlFlags, Length = descriptor.BinaryLength,
        Owner = descriptor.Owner?.Value, Group = descriptor.Group?.Value, Hex = Convert.ToHexString(Bytes(descriptor)),
        Sacl = AclHex(descriptor is RawSecurityDescriptor raw ? raw.SystemAcl : ((CommonSecurityDescriptor)descriptor).SystemAcl),
        Dacl = AclHex(descriptor is RawSecurityDescriptor raw2 ? raw2.DiscretionaryAcl : ((CommonSecurityDescriptor)descriptor).DiscretionaryAcl),
        ResourceManagerControl = descriptor is RawSecurityDescriptor raw3 ? (int?)raw3.ResourceManagerControl : null,
        IsContainer = descriptor is CommonSecurityDescriptor common ? (bool?)common.IsContainer : null,
        IsDS = descriptor is CommonSecurityDescriptor common2 ? (bool?)common2.IsDS : null,
        DaclCanonical = descriptor is CommonSecurityDescriptor common3 ? (bool?)common3.IsDiscretionaryAclCanonical : null,
        SaclCanonical = descriptor is CommonSecurityDescriptor common4 ? (bool?)common4.IsSystemAclCanonical : null,
    };
}

public partial class PortableSecurityFoundationTests
{
    private static object? ReplayDescriptorClosure(string operation, JsonElement arguments)
        => PortableDescriptorClosureDriver.Execute(operation, arguments.GetProperty("Scenario").GetInt32());
}
