namespace AdForLinux.FunctionalTests;

// Test orchestration only. Managed chain building is an observation, not a proxy
// for native WinLDAP validation. Native errors must propagate to the actual gate.
internal static class WindowsTlsDiagnosticControl
{
    internal static void ObserveThenRun(Func<bool> managedDiagnostic, Action nativeControl, out string managedOutcome)
    {
        try { managedOutcome = managedDiagnostic() ? "valid" : "not valid"; }
        catch (Exception error)
        {
            // Never emit certificate data, exception messages or inner exceptions.
            managedOutcome = $"exception HResult={error.HResult:X8}";
        }
        nativeControl();
    }
}
