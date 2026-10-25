using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;
using Referral = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

// Explicit standalone mode only. No test discovery, workflow or security setup.
public static class WindowsContinuationDiagnostic
{
    public static readonly string[] Names = ["onelevel/success", "onelevel/partial", "subtree/success", "subtree/partial"];
    public sealed record Observation(string Status, string Phase, string FailureKind, int FailureCode,
        bool Cleanup, int PoolDelta, int Attempts, int Sends, int[] Results, string[] Returned,
        int SourceBinds, int SourceSearches, int BindingReads, int SchemaReads, int Continuations,
        int References, int TargetBinds, int TargetSearches, bool IdentityValid, long Reused);
    public sealed record Comparison(string Status, bool Cleanup, Observation Ordinary, Observation Scoped);
    public sealed record Report(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> Native,
        IReadOnlyDictionary<string, Comparison> Continuations, string Supported, string Adverse, bool AllPassed);
    // Separate inventory/report: never reinterpret the historical continuation verdicts.
    public static readonly string[] ExternalNames = ["onelevel/external", "subtree/external"];
    public sealed record ExternalReport(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> Native,
        IReadOnlyDictionary<string, Comparison> ExternalScopes, string Supported, string Adverse, bool AllPassed);
    public static ExternalReport RunExternal(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native)
    {
        ContextScopedReadDiagnostic.Validate();
        var cases = ScheduleExternal(native, name => Execute(name, external: true));
        bool supported = native.Where(x => x.Key != "anonymous-direct").All(x => x.Value.Status == "passed") &&
            cases.Values.All(c => c.Status == "passed");
        bool adverse = native["anonymous-direct"].Status == "passed";
        return new(native, cases, supported ? "passed" : "failed", adverse ? "passed" : "failed", supported && adverse);
    }
    public static Dictionary<string, Comparison> ScheduleExternal(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Func<string, Comparison> execute) => ExternalNames.ToDictionary(n => n, n =>
            native["original-direct"].Status == "passed" && native["original-referral"].Status == "passed"
                ? execute(n) : new Comparison("skipped", true, Empty("skipped"), Empty("skipped")));
    private static Observation Empty(string status) => new(status, "not-started", "none", 0, true, 0, 0, 0, [], [], 0, 0, 0, 0, 0, 0, 0, 0, false, 0);
    public static Report Run(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native)
    {
        ContextScopedReadDiagnostic.Validate();
        return CreateReport(native, Schedule(native, name => Execute(name)));
    }
    public static Dictionary<string, Comparison> Schedule(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Func<string, Comparison> execute) => Names.ToDictionary(n => n, n =>
            native["original-direct"].Status == "passed" && native["original-referral"].Status == "passed"
                ? execute(n) : new Comparison("skipped", true, Empty("skipped"), Empty("skipped")));
    public static Report CreateReport(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        IReadOnlyDictionary<string, Comparison> cases)
    {
        bool supported = native.Where(x => x.Key != "anonymous-direct").All(x => x.Value.Status == "passed") &&
            cases.Count == Names.Length && Names.All(n => cases.TryGetValue(n, out var c) && c.Status == "passed");
        bool adverse = native["anonymous-direct"].Status == "passed";
        return new(native, cases, supported ? "passed" : "failed", adverse ? "passed" : "failed", supported && adverse);
    }
    private static Comparison Execute(string name, bool external = false)
    {
        var scope = name.StartsWith("onelevel/", StringComparison.Ordinal) ? SearchScope.OneLevel : SearchScope.Subtree;
        bool partial = name.EndsWith("/partial", StringComparison.Ordinal);
        // Separate endpoint lifetimes prevent late traffic being attributed to the next mode.
        var ordinary = Observe(scope, partial, scoped: false, external);
        var scoped = Observe(scope, partial, scoped: true, external);
        return Compare(ordinary, scoped);
    }
    internal static Comparison Compare(Observation ordinary, Observation scoped)
    {
        bool cleanup = ordinary.Cleanup && scoped.Cleanup;
        bool passed = cleanup && ordinary.Status == "passed" && scoped.Status == "passed" &&
            ordinary.Returned.SequenceEqual(scoped.Returned) && ordinary.Results.SequenceEqual(scoped.Results);
        return new(passed ? "passed" : "failed", cleanup, ordinary, scoped);
    }
    private static Observation Observe(SearchScope scope, bool partial, bool scoped, bool external)
    {
        int initial = LdapConnectionProvider.Snapshot.Total;
        long reused = LdapConnectionProvider.Snapshot.Reused;
        WindowsReferralEndpoint? source = null, target = null;
        string phase = "setup"; Exception? failure = null; bool cleanup = true;
        int attempts = 0; var returned = new List<string>();
        ContextScopedReadDiagnostic? diagnostic = null;
        try
        {
            target = new(tls: true) { ExpectedSearchScope = external ? scope : null,
                ResponseDn = external ? "CN=referred,CN=target" : "CN=target" };
            string urlScope = external ? scope == SearchScope.OneLevel ? "one" : "sub" : "base";
            source = new(tls: true) { ServeBindingResolution = true, ServeSyntheticSchema = true,
                ExpectedSearchScope = external ? scope : null,
                ContinuationScope = external ? null : scope, ContinuationPartial = partial,
                ReferralUrl = $"ldaps://127.0.0.1:{target.Port}/CN=target??{urlScope}?(objectClass=*)" };
            phase = "context";
            var context = WindowsLdapContextQuery.Capture(); Require(context.HasValue);
            diagnostic = new(continuationScope: scope);
            using var root = new Entry($"LDAP://127.0.0.1:{source.Port}/CN=target",
                WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.Password,
                AdForLinux.DirectoryServices.AuthenticationTypes.SecureSocketsLayer);
            using var searcher = new Searcher(root) { SearchScope = (AdForLinux.DirectoryServices.SearchScope)(int)scope,
                ReferralChasing = Referral.External, PageSize = 0 };
            root.Options.Referral = Referral.None;
            diagnostic.Track(WindowsContextCandidateDiagnostic.BindingResolutionKey(root));
            phase = "selection";
            Require(!LdapConnectionProvider.IsContextScopedReadConfiguration(root.BuildOptions(), Referral.External,
                new SearchRequest("CN=target", "(objectClass=*)", scope) { SizeLimit = 1 }));
            for (int i = 0; i < 2; i++)
            {
                phase = "read"; attempts++;
                var result = scoped ? searcher.FindOneContextDiagnostic(diagnostic) : searcher.FindOneOrdinaryDiagnostic(diagnostic);
                Require(result is not null && result.Properties["description"][0] as string == WindowsReferralEndpoint.FirstIdentity);
                var path = result!.Path;
                returned.Add(path.EndsWith("/CN=local,CN=target", StringComparison.Ordinal) ? "local" :
                    path.EndsWith(external ? "/CN=referred,CN=target" : "/CN=target", StringComparison.Ordinal) ? "target" : "unexpected");
                Require(returned[^1] != "unexpected");
            }
            phase = "context-after"; Require(context == WindowsLdapContextQuery.Capture());
            phase = "complete";
        }
        catch (Exception e) { failure = e; }
        finally
        {
            // Quiesce both endpoints before interpreting counts, even after another cleanup fails.
            cleanup = CleanupAll(
                () => diagnostic?.Dispose(),
                () => { if (source is not null) source.DisposeAsync().AsTask().GetAwaiter().GetResult(); },
                () => { if (target is not null) target.DisposeAsync().AsTask().GetAwaiter().GetResult(); });
        }
        int poolDelta = LdapConnectionProvider.Snapshot.Total - initial;
        cleanup &= poolDelta == 0;
        var c = source is not null && target is not null ? Counts(source, target) : new int[8];
        bool identityValid = source is not null && target is not null && IdentityValid(source, target);
        long reuseDelta = LdapConnectionProvider.Snapshot.Reused - reused;
        if (failure is null)
        {
            try
            {
                phase = "counts";
                Require(external ? ExternalCountsMatch(c, scoped) : CountsMatch(c, scoped, partial));
                if (external) Require(returned.SequenceEqual(new[] { "target", "target" }));
                Require(diagnostic!.Sends == 2 && diagnostic.Results.SequenceEqual(new[] { partial ? 4 : 0, partial ? 4 : 0 }));
                Require(reuseDelta == (scoped && !partial ? 1 : 0));
                phase = "target-evidence"; Require(c[6] >= 1 && c[7] == 2 && identityValid);
                phase = "complete";
            }
            catch (Exception e) { failure = e; }
        }
        return new(failure is null && cleanup ? "passed" : "failed", phase, Kind(failure), Code(failure), cleanup, poolDelta,
            attempts, diagnostic?.Sends ?? 0, diagnostic?.Results ?? [], returned.ToArray(),
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], identityValid, reuseDelta);
    }
    internal static bool CleanupAll(params Action[] actions)
    {
        bool clean = true;
        foreach (var action in actions) try { action(); } catch { clean = false; }
        return clean;
    }
    internal static bool CountsMatch(int[] c, bool scoped, bool partial) =>
        c.Length == 8 && c[0] == (scoped ? partial ? 5 : 4 : 3) && c[1] == 7 &&
        c[2] == 1 && c[3] == 4 && c[4] == 2 && c[5] == 2 && c[6] >= 1 && c[7] == 2;
    internal static bool ExternalCountsMatch(int[] c, bool scoped) =>
        c.Length == 8 && c[0] == (scoped ? 4 : 3) && c[1] == 7 && c[2] == 1 && c[3] == 4 &&
        c[4] == 0 && c[5] == 0 && c[6] >= 1 && c[7] == 2;
    private static int[] Counts(WindowsReferralEndpoint s, WindowsReferralEndpoint t) =>
        [s.Binds, s.Searches, s.BindingReads, s.SchemaReads, s.ContinuationReads, s.ContinuationReferences, t.Binds, t.Searches];
    private static bool IdentityValid(WindowsReferralEndpoint s, WindowsReferralEndpoint t) =>
        s.AnonymousBinds == 0 && s.SaslBinds == 0 && t.AnonymousBinds == 0 && t.SaslBinds == 0 &&
        s.BoundIdentities.All(i => i == WindowsReferralEndpoint.FirstIdentity) && t.BoundIdentities.All(i => i == WindowsReferralEndpoint.FirstIdentity);
    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Continuation comparison assertion failed."); }
    private static string Kind(Exception? e) => e switch { null => "none", LdapException => "ldap", DirectoryOperationException => "directory", _ => "fixture" };
    private static int Code(Exception? e) => e switch { null => 0, LdapException l => l.ErrorCode, DirectoryOperationException { Response: not null } d => (int)d.Response.ResultCode, _ => e.HResult };
}
