using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;
using Referral = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

// Standalone only, no test discovery or automatic workflow. Real context reader,
// shared candidate send core and shared FindOne core; never the raw pool bypass.
public static class WindowsContextCandidateDiagnostic
{
    public sealed record Observation(string Status, int Checks, int Attempts, int SourceBinds, int SourceSearches,
        int TargetBinds, int TargetSearches, int FailureCode, bool InstrumentationFailed, bool Cleanup, int PoolDelta, int FreshCode = 0, int WarmCode = 0, int ObservedCode = 0, string FailureKind = "success", string FreshKind = "success", string WarmKind = "success", string ObservedKind = "success");
    public static readonly string[] PerIdentity = ["stable", "failed-bind", "primary-failure", "target-failure", "findone"];
    public static readonly string[] Boundaries = ["acquired", "send", "complete", "return"];
    public static string[] CaseNames => new[] { "original", "a", "b" }.SelectMany(i => PerIdentity.Select(c => i + "/" + c))
        .Concat(new[] { "a-to-b", "b-to-a" }.SelectMany(i => Boundaries.Select(c => i + "/" + c)))
        .Concat(new[] { "anonymous/first", "anonymous/repeated", "anonymous/primary", "partition/a-b-a" })
        .Concat(Boundaries.Select(c => "anonymous/" + c)).ToArray();

    public static Dictionary<string, Observation> Run(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Action<Action> accountA, Action<Action> accountB)
    {
        ContextScopedReadDiagnostic.Validate();
        var scopes = new Dictionary<string, Action<Action>> { ["original"] = a => a(), ["a"] = accountA, ["b"] = accountB };
        return Schedule(native, name => Observe(name, scopes));
    }
    public static Dictionary<string, Observation> Schedule(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Func<string, Observation> execute)
    {
        var result = new Dictionary<string, Observation>();
        foreach (var name in CaseNames)
        {
            var owner = name.Split('/')[0];
            var identities = owner is "a-to-b" or "b-to-a" or "partition" ? new[] { "a", "b" }
                : new[] { owner == "anonymous" ? "original" : owner };
            result[name] = identities.All(i => native[i + "-direct"].Status == "passed" && native[i + "-referral"].Status == "passed")
                ? execute(name) : new("skipped", 0, 0, 0, 0, 0, 0, 0, false, false, 0);
        }
        return result;
    }
    public sealed record Report(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> Native,
        IReadOnlyDictionary<string, Observation> Candidate, string Supported, string Adverse, bool AllPassed);
    public static Report CreateReport(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        IReadOnlyDictionary<string, Observation> candidate)
    {
        bool supported = native.Where(p => p.Key != "anonymous-direct").All(p => p.Value.Status == "passed") &&
            candidate.Count == CaseNames.Length && candidate.Values.All(v => v.Status == "passed");
        bool adverse = native["anonymous-direct"].Status == "passed";
        return new(native, candidate, supported ? "passed" : "failed", adverse ? "passed" : "failed", supported && adverse);
    }

    private static Observation Observe(string name, Dictionary<string, Action<Action>> scopes)
    {
        Fixture? f = null; Exception? failure = null; bool cleanup = true;
        int initial = LdapConnectionProvider.Snapshot.Total;
        try
        {
            f = new Fixture(); // Always create endpoint/key under runner, before entering scopes.
            string owner = name.Split('/')[0], scenario = name.Split('/')[1];
            if (owner is "a-to-b" or "b-to-a")
                Transition(f, scopes[owner[..1]], scopes[owner[^1..]], scenario);
            else if (owner == "anonymous") Anonymous(f, scenario);
            else if (owner == "partition") Partition(f, scopes["a"], scopes["b"]);
            else scopes[owner](() => Execute(f, scenario));
            f.Require(!f.InstrumentationFailed);
            f.Require(f.Source.AnonymousBinds == 0 && f.Source.SaslBinds == 0 &&
                f.Target.AnonymousBinds == 0 && f.Target.SaslBinds == 0 &&
                f.Source.BoundIdentities.All(i => i == WindowsReferralEndpoint.FirstIdentity) &&
                f.Target.BoundIdentities.All(i => i == WindowsReferralEndpoint.FirstIdentity));
        }
        catch (Exception e) { failure = e; }
        finally
        {
            if (f is not null) try { f.Dispose(); } catch { cleanup = false; }
        }
        int delta = LdapConnectionProvider.Snapshot.Total - initial;
        cleanup &= delta == 0;
        return new(failure is null && cleanup ? "passed" : "failed", f?.Checks ?? 0, f?.Attempts ?? 0,
            f?.Source.Binds ?? 0, f?.Source.Searches ?? 0, f?.Target.Binds ?? 0, f?.Target.Searches ?? 0,
            Code(failure), f?.InstrumentationFailed ?? false, cleanup, delta, f?.FreshCode ?? 0, f?.WarmCode ?? 0, f?.ObservedCode ?? 0, Kind(failure), f?.FreshKind ?? "success", f?.WarmKind ?? "success", f?.ObservedKind ?? "success");
    }
    private static string Kind(Exception? e) => e switch { null => "success", LdapException => "ldap", DirectoryOperationException { Response: not null } => "directory", DirectoryOperationException => "directory-no-response", _ => "fixture" };
    private static int Code(Exception? e) => e switch { null => 0, LdapException l => l.ErrorCode, DirectoryOperationException d when d.Response is not null => (int)d.Response.ResultCode, _ => e.HResult };
    private static void Execute(Fixture f, string scenario)
    {
        var context = WindowsLdapContextQuery.Capture(); f.Require(context.HasValue);
        switch (scenario)
        {
            case "stable":
                f.Read(); f.Read(); f.Read();
                f.Require(context == WindowsLdapContextQuery.Capture());
                f.Require(f.Source.Binds == 1 && f.Target.Searches == 3); break;
            case "failed-bind":
                f.Source.RejectBinds = true;
                var observed = Capture(() => f.Read()); f.ObservedCode = Code(observed); f.ObservedKind = Kind(observed); f.Require(observed is LdapException { ErrorCode: 49 });
                f.Require(f.Source.Searches == 0 && f.Target.Searches == 0);
                f.Source.RejectBinds = false;
                f.Require(LdapConnectionProvider.Snapshot.Total == f.Initial);
                f.Read(); f.Require(f.Source.Binds >= 2 && f.Target.Searches == 1); break;
            case "primary-failure":
            case "target-failure":
                f.Read(); var endpoint = scenario == "primary-failure" ? f.Source : f.Target;
                endpoint.DisconnectOnSearch = true;
                var transport = Capture(() => f.Read()); f.ObservedCode = Code(transport); f.ObservedKind = Kind(transport); f.Require(IsTransportFailure(transport));
                f.Require(LdapConnectionProvider.Snapshot.Total == f.Initial);
                endpoint.DisconnectOnSearch = false;
                f.Read(); f.Require(f.Attempts == 3 && f.Source.Binds >= 2); break;
            case "findone":
                f.Source.ServeSyntheticSchema = true;
                using (var root = new Entry($"LDAP://127.0.0.1:{f.Source.Port}/CN=target",
                    WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.Password,
                    AdForLinux.DirectoryServices.AuthenticationTypes.SecureSocketsLayer))
                using (var searcher = new Searcher(root) { SearchScope = AdForLinux.DirectoryServices.SearchScope.Base,
                    ReferralChasing = Referral.External, PageSize = 0 })
                {
                    root.Options.Referral = Referral.None; // Deliberately differs from searcher.
                    for (int i = 0; i < 2; i++)
                    {
                        f.Attempts++;
                        var result = searcher.FindOneContextDiagnostic(f.Diagnostic);
                        f.Require(result?.Properties["description"][0] as string == WindowsReferralEndpoint.FirstIdentity);
                    }
                    // One pooled primary, two fresh schema binds, each reading rootDSE and schema.
                    f.Require(f.Source.Binds == 3 && f.Source.Searches == 6 && f.Source.SchemaReads == 4 && f.Target.Searches == 2);
                }
                break;
            default: throw new InvalidOperationException("Unknown candidate scenario.");
        }
    }
    private static void Transition(Fixture f, Action<Action> first, Action<Action> second, string stage)
    {
        WindowsLdapContext? before = null, changed = null;
        f.SetBoundary((point, run) =>
        {
            if (point != stage) { run(); return; }
            second(() => { changed = WindowsLdapContextQuery.Capture(); run(); });
        });
        first(() => { before = WindowsLdapContextQuery.Capture(); f.Require(before.HasValue); f.Read(); });
        f.Require(changed.HasValue && before != changed);
        f.Require(f.Source.Searches == 1 && f.Target.Searches == 1 && f.Attempts == 1);
        f.Require(LdapConnectionProvider.Snapshot.Total == f.Initial);
    }
    private static void Partition(Fixture f, Action<Action> a, Action<Action> b)
    {
        WindowsLdapContext? ca = null, cb = null;
        // Keep A's scope alive across B, avoiding assumptions about token copies
        // created by separate RunImpersonated calls.
        a(() =>
        {
            ca = WindowsLdapContextQuery.Capture(); f.Read();
            b(() => { cb = WindowsLdapContextQuery.Capture(); f.Read(); });
            f.Require(ca == WindowsLdapContextQuery.Capture()); f.Read();
        });
        f.Require(ca.HasValue && cb.HasValue && ca != cb);
        f.Require(f.Source.Binds == 2 && f.Target.Searches == 3);
    }
    private static void Anonymous(Fixture f, string scenario)
    {
        if (Boundaries.Contains(scenario))
        {
            f.SetBoundary((stage, run) =>
            {
                if (stage == scenario) WindowsAuthenticatedDiagnostic.Anonymous(() =>
                { f.Require(WindowsLdapContextQuery.Capture() is null); run(); });
                else run();
            });
            var error = Capture(() => f.Read());
            if (scenario is "complete" or "return") f.Require(error is null && f.Target.Searches == 1);
            else
            {
                // Same candidate with no cached selection is the fresh comparison.
                f.SetBoundary(null);
                Exception? fresh = null;
                WindowsAuthenticatedDiagnostic.Anonymous(() => fresh = Capture(() => f.Read()));
                f.WarmCode = Code(error); f.FreshCode = Code(fresh); f.WarmKind = Kind(error); f.FreshKind = Kind(fresh);
                f.Require(IsNativeOrSuccess(error) && IsNativeOrSuccess(fresh) && Kind(error) == Kind(fresh) && Code(error) == Code(fresh));
            }
            f.Require(LdapConnectionProvider.Snapshot.Total == f.Initial);
            return;
        }
        var referral = f.Source.ReferralUrl;
        if (scenario == "primary") f.Source.ReferralUrl = null;
        Exception? freshError = null, warmError = null;
        var beforeFresh = (Source: f.Source.Binds, Target: f.Target.Binds, Searches: f.Target.Searches);
        WindowsAuthenticatedDiagnostic.Anonymous(() => freshError = Capture(() => f.Read()));
        var freshDelta = (f.Source.Binds - beforeFresh.Source, f.Target.Binds - beforeFresh.Target, f.Target.Searches - beforeFresh.Searches);
        if (scenario == "first") f.Source.ReferralUrl = null;
        f.Read();
        f.Source.ReferralUrl = scenario == "primary" ? null : referral;
        long reused = LdapConnectionProvider.Snapshot.Reused;
        var beforeWarm = (Source: f.Source.Binds, Target: f.Target.Binds, Searches: f.Target.Searches);
        WindowsAuthenticatedDiagnostic.Anonymous(() =>
        { f.Require(WindowsLdapContextQuery.Capture() is null); warmError = Capture(() => f.Read()); });
        f.FreshCode = Code(freshError); f.WarmCode = Code(warmError); f.FreshKind = Kind(freshError); f.WarmKind = Kind(warmError);
        f.Require(IsNativeOrSuccess(freshError) && IsNativeOrSuccess(warmError) && Kind(freshError) == Kind(warmError) && Code(freshError) == Code(warmError));
        f.Require(LdapConnectionProvider.Snapshot.Reused == reused);
        f.Require(freshDelta == (f.Source.Binds - beforeWarm.Source, f.Target.Binds - beforeWarm.Target, f.Target.Searches - beforeWarm.Searches));
    }
    internal static bool IsTransportFailure(Exception? error) => error is LdapException { ErrorCode: 81 or 82 or 85 or 91 } ||
        error is DirectoryOperationException { Response.ResultCode: ResultCode.Unavailable or ResultCode.ProtocolError };
    private static bool IsNativeOrSuccess(Exception? error) => error is null or LdapException or DirectoryOperationException;
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception e) { return e; } }
    private sealed class Fixture : IDisposable
    {
        internal readonly WindowsReferralEndpoint Source, Target;
        internal readonly int Initial = LdapConnectionProvider.Snapshot.Total;
        internal int Checks, Attempts, FreshCode, WarmCode, ObservedCode;
        internal string FreshKind = "success", WarmKind = "success", ObservedKind = "success";
        internal ContextScopedReadDiagnostic Diagnostic = new();
        private readonly List<ContextScopedReadDiagnostic> diagnostics = [];
        internal bool InstrumentationFailed => Diagnostic.InstrumentationFailed || diagnostics.Any(d => d.InstrumentationFailed);
        internal Fixture()
        {
            Target = new(tls: true);
            try { Source = new(tls: true) { ReferralUrl = $"ldaps://127.0.0.1:{Target.Port}/CN=target??base?(objectClass=*)" }; }
            catch { Target.DisposeAsync().AsTask().GetAwaiter().GetResult(); throw; }
        }
        internal void SetBoundary(Action<string, Action>? action)
        { diagnostics.Add(Diagnostic); Diagnostic = new(action); }
        internal void Require(bool condition) { if (!condition) throw new InvalidOperationException("Candidate assertion failed."); Checks++; }
        internal void Read()
        {
            Attempts++;
            var response = LdapConnectionProvider.SendContextScopedReadDiagnostic(new()
            {
                Host = "127.0.0.1", Port = Source.Port, UseSsl = true,
                BindDn = WindowsReferralEndpoint.FirstIdentity, BindPassword = WindowsReferralEndpoint.Password,
                AuthenticationType = AuthType.Basic, Timeout = TimeSpan.FromSeconds(5)
            }, new SearchRequest("CN=target", "(objectClass=*)", SearchScope.Base, "description"), Diagnostic);
            Require(response.ResultCode == ResultCode.Success && response.Entries.Count == 1 &&
                response.Entries[0].Attributes["description"]?[0] as string == WindowsReferralEndpoint.FirstIdentity);
        }
        public void Dispose()
        {
            Exception? error = null;
            void Attempt(Action action) { try { action(); } catch (Exception e) { error ??= e; } }
            foreach (var d in diagnostics.Append(Diagnostic)) Attempt(d.Dispose);
            Attempt(() => Source.DisposeAsync().AsTask().GetAwaiter().GetResult());
            Attempt(() => Target.DisposeAsync().AsTask().GetAwaiter().GetResult());
            if (error is not null) throw error;
        }
    }
}
