using System.Runtime.Versioning;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using D = AdForLinux.DirectoryServices;
using M = System.DirectoryServices;
using MP = System.Security.Principal;

namespace AdForLinux.Examples;

// Compiled by the companion tests. No directory operation runs as part of compilation.
[SupportedOSPlatform("windows")]
public static class MicrosoftInteropUsage
{
    public static M.ActiveDirectorySecurity IndependentCopy(D.ActiveDirectorySecurity portable)
        => portable.ToMicrosoftObject();

    public static D.SecurityMasks ApplyLocalEdit(D.ActiveDirectorySecurity portable)
    {
        using MicrosoftSecurityEdit edit = portable.ExportForEdit();
        edit.Object.AddAccessRule(new M.ActiveDirectoryAccessRule(
            new MP.SecurityIdentifier("S-1-5-21-1-2-3-2000"),
            M.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
        return edit.ApplyTo(portable);
    }

    // Requires an entry with a complete exportable descriptor and a non-merging rule.
    // Saving is always an explicit caller operation. Offline tests never call this method.
    public static void EditAndSave(D.DirectoryEntry entry)
    {
        ApplyLocalEdit(entry.ObjectSecurity);
        entry.CommitChanges();
    }
}
