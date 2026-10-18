using System.Runtime.Versioning;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using D = AdForLinux.DirectoryServices;
using M = System.DirectoryServices;
using MP = System.Security.Principal;

namespace AdForLinux.Examples;

// Compiled by the companion tests. Export is one-way; no directory operation runs.
[SupportedOSPlatform("windows")]
public static class MicrosoftInteropUsage
{
    public static M.ActiveDirectorySecurity IndependentCopy(D.ActiveDirectorySecurity portable)
        => portable.ToMicrosoftObject();

    // Changes only the returned Microsoft object. To change portable state, use
    // the portable rule/mutation APIs directly; there is no import/apply-back API.
    public static M.ActiveDirectorySecurity EditIndependentCopy(D.ActiveDirectorySecurity portable)
    {
        var copy = portable.ToMicrosoftObject();
        copy.AddAccessRule(new M.ActiveDirectoryAccessRule(
            new MP.SecurityIdentifier("S-1-5-21-1-2-3-2000"),
            M.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
        return copy;
    }
}
