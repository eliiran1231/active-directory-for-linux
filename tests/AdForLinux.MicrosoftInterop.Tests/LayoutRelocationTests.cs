using AdForLinux.Tests.Shared;
using Xunit;
using M = System.DirectoryServices;
using P = System.Security.Principal;
using System.Security.AccessControl;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.MicrosoftInterop.Tests;

public class LayoutRelocationTests
{
    public static IEnumerable<object[]> Cases() => LayoutRelocationCases.Matrix();

    [WindowsTheory]
    [MemberData(nameof(Cases))]
    public void Native_accepts_independently_assembled_relocation_candidate(string section, bool grow, int gap, int fill)
    {
        // Actual Windows execution; no portable exporter or edit-back is involved.
        var native = new M.ActiveDirectorySecurity();
        native.SetSecurityDescriptorBinaryForm(LayoutRelocationCases.Image(section, grow, gap, fill, false));
        var sid = new P.SecurityIdentifier(grow ? U1 : Everyone, 0);
        if (section == "owner") native.SetOwner(sid);
        else if (section == "group") native.SetGroup(sid);
        else if (section == "sacl")
        {
            var rule = new M.ActiveDirectoryAuditRule(new P.SecurityIdentifier(U2, 0), M.ActiveDirectoryRights.ReadProperty, AuditFlags.Success);
            if (grow) native.AddAuditRule(rule); else native.RemoveAuditRuleSpecific(rule);
        }
        else
        {
            var rule = new M.ActiveDirectoryAccessRule(new P.SecurityIdentifier(U2, 0), M.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
            if (grow) native.AddAccessRule(rule); else native.RemoveAccessRuleSpecific(rule);
        }
        var candidate = new M.ActiveDirectorySecurity();
        var bytes = LayoutRelocationCases.Image(section, grow, gap, fill, true);
        var unchanged = (byte[])bytes.Clone();
        candidate.SetSecurityDescriptorBinaryForm(bytes);
        Assert.Equal(unchanged, bytes);
        Assert.Equal(native.GetSecurityDescriptorBinaryForm(), candidate.GetSecurityDescriptorBinaryForm());
    }
}
