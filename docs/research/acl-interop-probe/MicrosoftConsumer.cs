// Compiled against the real Microsoft surface; executed only in the optional Windows branch.
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

[SupportedOSPlatform("windows")]
sealed class MicrosoftHookProbe : M.ActiveDirectorySecurity
{
    private int accessCalls, auditCalls, nameCalls, handleCalls, boolCalls;
    protected override bool ModifyAccess(E.AccessControlModification modification, E.AccessRule rule, out bool modified)
    {
        accessCalls++;
        WriteLock();
        try { AccessRulesModified = true; modified = true; return true; }
        finally { WriteUnlock(); }
    }
    protected override bool ModifyAudit(E.AccessControlModification modification, E.AuditRule rule, out bool modified)
    { auditCalls++; AuditRulesModified = true; modified = true; return true; }
    protected override void Persist(string name, E.AccessControlSections sections) => nameCalls++;
    protected override void Persist(SafeHandle handle, E.AccessControlSections sections) => handleCalls++;
    protected override void Persist(bool ownership, string name, E.AccessControlSections sections) => boolCalls++;
    public static void Run()
    {
        var value = new MicrosoftHookProbe();
        var sid = new B.SecurityIdentifier("S-1-1-0");
        var access = new M.ActiveDirectoryAccessRule(sid, M.ActiveDirectoryRights.ReadProperty, E.AccessControlType.Allow);
        var audit = new M.ActiveDirectoryAuditRule(sid, M.ActiveDirectoryRights.ReadProperty, E.AuditFlags.Success);
        E.ObjectSecurity baseView = value;
        baseView.ModifyAccessRule(E.AccessControlModification.Add, access, out _);
        baseView.ModifyAuditRule(E.AccessControlModification.Add, audit, out _);
        value.AddAccessRule(access); // Real managed BCL helper, expected to bypass protected hook.
        if (value.accessCalls != 1 || value.auditCalls != 1) throw new Exception("Microsoft hook dispatch differs.");
        value.Persist("fixture", E.AccessControlSections.Access);
        using var handle = new EmptyHandle();
        value.Persist(handle, E.AccessControlSections.Access);
        value.Persist(true, "fixture", E.AccessControlSections.Access); // Our override only, no privilege call.
        value.CallBaseFalse();
        if (value.nameCalls != 2 || value.handleCalls != 1 || value.boolCalls != 1) throw new Exception("Microsoft Persist dispatch differs.");
        Console.WriteLine("PASS real Microsoft managed hook paths (Windows only).");
    }
    private void CallBaseFalse() => base.Persist(false, "fixture", E.AccessControlSections.Access);
    // Never call base.Persist(true,...): that may invoke native privilege management.
}
