using System.Runtime.InteropServices;
using Ms = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

internal static class CompatibilityOwnedDirectoryObjects
{
    // Call before enabling cleanup for a generated DN. An existing entry or
    // any authentication/connectivity failure must abort without deleting it.
    // Full-GUID CNs plus the isolated lab scope prevent ordinary name reuse;
    // this preflight also detects objects already present at that exact DN.
    internal static void RequireAbsent(string distinguishedName)
    {
        using var probe = new Ms.DirectoryEntry(DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        try { probe.RefreshCache(new[] { "distinguishedName" }); }
        catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030))
        {
            return;
        }
        throw new InvalidOperationException(
            $"Refusing to create or clean up the already-existing test DN: {distinguishedName}");
    }
}
