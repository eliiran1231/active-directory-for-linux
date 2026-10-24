using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices.Ldap;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

// Explicit standalone-worker callbacks only. No Fact/Theory, no CI discovery.
public static class WindowsAuthenticatedDiagnostic
{
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateAnonymousToken(IntPtr thread);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    internal static void Anonymous(Action action)
    {
        if (!ImpersonateAnonymousToken(GetCurrentThread())) throw new InvalidOperationException("Anonymous scope unavailable.");
        try { action(); }
        finally { if (!RevertToSelf()) { TerminateProcess(GetCurrentProcess(), 86); Environment.Exit(86); } }
    }
    public sealed record Observation(string Status, int Connections, int Tls, int Binds,
        int Searches, int Anonymous, int Sasl, int PrimaryBinds = 0, int PrimarySearches = 0, int Closed = 0,
        string Phase = "complete", string FailureKind = "none", int FailureCode = 0);

    public static Dictionary<string, Observation> Run(Action<Action> accountA, Action<Action> accountB)
    {
        var scopes = new Dictionary<string, Action<Action>> { ["original"] = action => action(), ["a"] = accountA, ["b"] = accountB, ["anonymous"] = Anonymous };
        return Schedule((identity, stage) => stage == "transition"
            ? Observe(scopes[identity[..1]], true, true, scopes[identity[^1..]])
            : Observe(scopes[identity], stage != "direct", stage == "retained-primary"));
    }

    // Pure scheduler is also executed with injected observations by --self-test.
    public static Dictionary<string, Observation> Schedule(Func<string, string, Observation> observe)
    {
        var results = new Dictionary<string, Observation>();
        foreach (var identity in new[] { "original", "a", "b" })
        {
            results[identity + "-direct"] = SafeObserve(identity, "direct");
            results[identity + "-referral"] = Passed(identity + "-direct") ? SafeObserve(identity, "referral") : Skipped();
            results[identity + "-retained-primary"] = Passed(identity + "-referral") ? SafeObserve(identity, "retained-primary") : Skipped();
        }
        foreach (var direction in new[] { "a-to-b", "b-to-a" })
        {
            results[direction] = Passed("a-retained-primary") && Passed("b-retained-primary")
                ? SafeObserve(direction, "transition") : Skipped();
        }
        results["anonymous-direct"] = SafeObserve("anonymous", "direct"); // Separate negative control, never a gate for A/B.
        return results;
        bool Passed(string name) => results[name].Status == "passed";
        Observation SafeObserve(string identity, string stage)
        {
            try { return observe(identity, stage); }
            catch { return new("failed", 0, 0, 0, 0, 0, 0); }
        }
    }

    private static Observation Skipped() => new("skipped", 0, 0, 0, 0, 0, 0);
    private static Observation Observe(Action<Action> firstScope, bool referral, bool reuse, Action<Action>? secondScope = null)
    {
        WindowsReferralEndpoint? source = null, target = null;
        string status = "failed";
        string phase = "initialization", failureKind = "none";
        int failureCode = 0;
        try
        {
            // Endpoints and key loading always happen before impersonation.
            target = new WindowsReferralEndpoint(tls: true);
            if (referral)
            {
                source = new WindowsReferralEndpoint(tls: true)
                { ReferralUrl = $"ldaps://127.0.0.1:{target.Port}/CN=target??base?(objectClass=*)" };
            }
            foreach (string identity in new[] { WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.SecondIdentity })
            {
                LdapConnection? retained = null;
                try
                {
                    firstScope(() =>
                    {
                        phase = "create";
                        retained = LdapConnectionFactory.Create(new LdapConnectionOptions
                        {
                            Host = "127.0.0.1", Port = (source ?? target).Port, UseSsl = true,
                            AuthenticationType = AuthType.Basic, BindDn = identity,
                            BindPassword = WindowsReferralEndpoint.Password, Timeout = TimeSpan.FromSeconds(5),
                        });
                        LdapConnectionFactory.ConfigureReferralChasing(retained,
                            referral ? ReferralChasingOption.External : ReferralChasingOption.None);
                        // Normal WinLDAP certificate validation. No callback or auth override.
                        phase = "bind";
                        retained.Bind();
                        phase = "search";
                        Read(retained, identity);
                    });
                    if (reuse) (secondScope ?? firstScope)(() => { phase = "search"; Read(retained!, identity); });
                }
                finally { retained?.Dispose(); }
            }
            int expectedSearches = reuse ? 4 : 2;
            if (target.Searches != expectedSearches || target.TlsHandshakes < 1 ||
                target.AnonymousBinds != 0 || target.SaslBinds != 0 ||
                target.BoundIdentities.Any(x => x != WindowsReferralEndpoint.FirstIdentity && x != WindowsReferralEndpoint.SecondIdentity))
                throw new InvalidOperationException("Native target observation mismatch.");
            status = "passed";
            phase = "complete";
        }
        catch (Exception error)
        {
            status = "failed";
            (failureKind, failureCode) = error switch
            {
                LdapException ldap => ("ldap", ldap.ErrorCode),
                DirectoryOperationException operation => ("directory", operation.Response is null ? operation.HResult : (int)operation.Response.ResultCode),
                System.ComponentModel.Win32Exception native => ("native", native.NativeErrorCode),
                _ => ("fixture", error.HResult),
            }; // Fixed kinds/numeric codes only, never messages or native payloads.
        }
        finally
        {
            try { source?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { status = "failed"; }
            try { target?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { status = "failed"; }
        }
        return new(status, target?.Connections ?? 0, target?.TlsHandshakes ?? 0,
            target?.Binds ?? 0, target?.Searches ?? 0, target?.AnonymousBinds ?? 0, target?.SaslBinds ?? 0,
            source?.Binds ?? 0, source?.Searches ?? 0, target?.Closed ?? 0, phase, failureKind, failureCode);
    }
    private static void Read(LdapConnection connection, string identity)
    {
        var response = (SearchResponse)connection.SendRequest(new SearchRequest("CN=source", "(objectClass=*)", SearchScope.Base, "description"));
        if (response.ResultCode != ResultCode.Success || response.Entries.Count != 1 ||
            response.Entries[0].Attributes["description"]?[0] is not string actual || actual != identity)
            throw new InvalidOperationException("Native identity/search mismatch.");
    }
}
