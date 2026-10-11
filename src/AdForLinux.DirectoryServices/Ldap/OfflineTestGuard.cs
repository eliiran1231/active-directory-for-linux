namespace AdForLinux.DirectoryServices.Ldap;

// Explicit process-wide test mode. Capture once so later environment changes
// cannot reopen live access in an already guarded test process.
internal static class OfflineTestGuard
{
    internal const string Variable = "ADFL_OFFLINE_TESTS";
    internal const string Message = "Offline test mode blocks live directory access and fixture provisioning.";
    internal static readonly bool Enabled = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(Variable));

    internal static void RequireLiveAccess()
    {
        if (Enabled) throw new InvalidOperationException(Message);
    }
}
