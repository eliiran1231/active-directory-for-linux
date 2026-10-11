#pragma warning disable CA1416 // Shared framework enum values only; all operations here use portable objects.
using System.Security.AccessControl;
using D = AdForLinux.DirectoryServices;
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.Tests.Shared;

internal static class DetachedCoverageCases
{
    internal static byte[] Baseline() => Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 0x40, 16, U1)));
    internal static byte[] Replacement() => Build(U2, U2, Acl(4, Ace(0, 0, 32, U2)), Acl(4, Ace(2, 0x40, 32, U2)), extraControl: 0x3000);
    internal static IEnumerable<object[]> Matrix()
    {
        var edits = new (string, D.SecurityMasks)[]
        {
            ("owner", D.SecurityMasks.Owner), ("group", D.SecurityMasks.Group),
            ("binary-owner", D.SecurityMasks.Owner), ("binary-group", D.SecurityMasks.Group),
            ("binary-dacl", D.SecurityMasks.Dacl), ("binary-sacl", D.SecurityMasks.Sacl), ("binary-all", (D.SecurityMasks)15),
            ("sddl-owner", D.SecurityMasks.Owner), ("sddl-group", D.SecurityMasks.Group),
            ("sddl-dacl", D.SecurityMasks.Dacl), ("sddl-sacl", D.SecurityMasks.Sacl), ("sddl-all", (D.SecurityMasks)15),
            ("protect-dacl", D.SecurityMasks.Dacl), ("protect-sacl", D.SecurityMasks.Sacl),
            ("modify-dacl", D.SecurityMasks.Dacl), ("modify-sacl", D.SecurityMasks.Sacl),
            ("typed-add-dacl", D.SecurityMasks.Dacl), ("typed-add-sacl", D.SecurityMasks.Sacl)
        };
        foreach (var mask in new[] { 0, 1, 2, 4, 8, 15 })
            foreach (var (name, sections) in edits) yield return new object[] { mask, name, (int)sections };
    }

    internal static void Apply(D.ActiveDirectorySecurity source, string operation)
    {
        // Exercise inherited/base-class routes as well as the typed AD ACL helpers.
        A.ObjectSecurity security = source;
        var sid = new P.SecurityIdentifier(U2, 0);
        var access = new D.ActiveDirectoryAccessRule(sid, D.ActiveDirectoryRights.WriteProperty, AccessControlType.Allow);
        var audit = new D.ActiveDirectoryAuditRule(sid, D.ActiveDirectoryRights.WriteProperty, AuditFlags.Success);
        var suffix = operation[(operation.IndexOf('-') + 1)..];
        var sections = suffix switch
        {
            "owner" => AccessControlSections.Owner, "group" => AccessControlSections.Group,
            "dacl" => AccessControlSections.Access, "sacl" => AccessControlSections.Audit,
            _ => AccessControlSections.All
        };
        switch (operation)
        {
            case "owner": security.SetOwner(sid); return;
            case "group": security.SetGroup(sid); return;
            case "protect-dacl": security.SetAccessRuleProtection(true, false); return;
            case "protect-sacl": security.SetAuditRuleProtection(true, false); return;
            case "modify-dacl": security.ModifyAccessRule(AccessControlModification.Add, access, out _); return;
            case "modify-sacl": security.ModifyAuditRule(AccessControlModification.Add, audit, out _); return;
            case "typed-add-dacl": source.AddAccessRule(access); return;
            case "typed-add-sacl": source.AddAuditRule(audit); return;
            case "binary-all": security.SetSecurityDescriptorBinaryForm(Replacement()); return;
            case "sddl-all": security.SetSecurityDescriptorSddlForm(new A.RawSecurityDescriptor(Replacement(), 0).GetSddlForm(AccessControlSections.All)); return;
        }
        if (operation.StartsWith("binary-")) security.SetSecurityDescriptorBinaryForm(Replacement(), sections);
        else security.SetSecurityDescriptorSddlForm(new A.RawSecurityDescriptor(Replacement(), 0).GetSddlForm(AccessControlSections.All), sections);
    }
}
