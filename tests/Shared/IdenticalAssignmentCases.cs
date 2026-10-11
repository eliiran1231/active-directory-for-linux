#pragma warning disable CA1416
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.Tests.Shared;

internal static class IdenticalAssignmentCases
{
    internal const SecurityMasks All = (SecurityMasks)15;
    internal static SecurityMasks Target(bool audit) => audit ? SecurityMasks.Sacl : SecurityMasks.Dacl;
    internal static byte[] Baseline(bool audit,bool retainedInteger = false)
    {
        var condition = Convert.FromHexString("61727478F90A0000004C006500760065006C0001020000000000000003028500");
        var opposite = retainedInteger
            ? Ace(audit ? (byte)9 : (byte)13,audit ? (byte)0 : (byte)64,16,U1,condition)
            : Ace(audit ? (byte)0 : (byte)2,audit ? (byte)0 : (byte)64,16,U1);
        return audit ? Build(U1,U1,Acl(4,opposite),extraControl:0x2010)
            : Build(U1,U1,null,Acl(4,opposite));
    }
    internal static void EditAcl(ActiveDirectorySecurity source,bool audit)
    {
        var identity = new SecurityIdentifier(U2,0);
        if (audit) source.AddAuditRule(new ActiveDirectoryAuditRule(identity,ActiveDirectoryRights.WriteProperty,AuditFlags.Success));
        else source.AddAccessRule(new ActiveDirectoryAccessRule(identity,ActiveDirectoryRights.WriteProperty,AccessControlType.Allow));
    }
    internal static byte[] CompoundReplacement() => Build(U1,U2,Acl(4,Ace(0,0,32,U2)),Acl(4,Ace(2,64,32,U2)));
}
