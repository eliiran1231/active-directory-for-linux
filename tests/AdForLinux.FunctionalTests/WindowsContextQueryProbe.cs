using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.FunctionalTests;

// Existing runner token only. No LDAP, anonymous impersonation, account/logon,
// key/certificate creation, token duplication/modification or trust access.
public static class WindowsContextQueryProbe
{
    public sealed record Result(string FirstStage, string FirstKind, int FirstCode,
        string SecondStage, string SecondKind, int SecondCode, bool Eligible, bool Stable);
    public static Result Run()
    {
        OfflineTestGuard.RequireLiveAccess();
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
            throw new InvalidOperationException("Hosted Windows read-only token probe required.");
        var first = WindowsLdapContextQuery.Capture(out var a);
        var second = WindowsLdapContextQuery.Capture(out var b);
        return new(a.Stage, a.Kind, a.Code, b.Stage, b.Kind, b.Code,
            first.HasValue && second.HasValue, first.HasValue && first == second);
    }
}
