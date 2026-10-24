namespace AdForLinux.FunctionalTests;

// Anonymous adverse conditions remain visible and keep the overall result failing.
// Supported is separate so that anonymous failure cannot erase authenticated evidence.
public sealed record WindowsDiagnosticReport(
    Dictionary<string, WindowsAuthenticatedDiagnostic.Observation> Native,
    Dictionary<string, WindowsReferralPoolDiagnostic.Observation> Pool,
    string Supported, string Adverse)
{
    public static WindowsDiagnosticReport Create(Dictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Dictionary<string, WindowsReferralPoolDiagnostic.Observation> pool) => new(native, pool,
        native.Where(x => x.Key != "anonymous-direct").All(x => x.Value.Status == "passed") &&
        pool.Count == 3 * WindowsReferralPoolDiagnostic.Cases.Length + WindowsReferralPoolDiagnostic.Transitions.Length && pool.Values.All(x => x.Status == "passed") ? "passed" : "failed",
        native["anonymous-direct"].Status == "passed" ? "passed" : "failed");
    public bool AllPassed => Supported == "passed" && Adverse == "passed";
}
