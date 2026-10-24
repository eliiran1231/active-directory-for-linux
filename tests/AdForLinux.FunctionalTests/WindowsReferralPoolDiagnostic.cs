using System.DirectoryServices.Protocols;
using System.Security.Principal;
using AdForLinux.DirectoryServices.Ldap;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

// Standalone diagnostic only: never discovered as a test or enabled by production.
public static class WindowsReferralPoolDiagnostic
{
    public sealed record Observation(string Status, int Checks = 0, int PrimaryBinds = 0,
        int TargetConnections = 0, int TargetTls = 0, int TargetBinds = 0, int TargetSearches = 0,
        int Anonymous = 0, int Sasl = 0, int Closed = 0, int ManagedAttempts = 0,
        int BaselineCredentialed = 0, int PooledCredentialed = 0, bool Cleanup = false,
        string FailureKind = "none", int FailureCode = 0, string ObservedFailureKind = "none", int ObservedFailureCode = 0,
        int CleanupMask = 0, int LeaseCleanupCode = 0, int KeyCleanupCode = 0, int OtherCleanupCode = 0,
        int SourceCleanupCode = 0, int TargetCleanupCode = 0, int PoolDelta = 0,
        int SourceAbandons = 0, int TargetAbandons = 0, int TargetTlsPrefixes = 0, int TargetBerPrefixes = 0, string FailurePoint = "none", int TargetRejectedTlsProbes = 0,
        int WorkersReady = 0, int OperationStarts = 0, int OverlapArrivals = 0, int OverlapTimeouts = 0, string Timeline = "", int TimelineDropped = 0);
    public static readonly string[] Cases = ["isolation", "concurrent", "unpooled-concurrent", "capacity", "generation", "failed-bind",
        "primary-disconnect", "target-disconnect", "target-bind-rejection", "untrusted-target", "mixed-referral"];
    public static readonly string[] Transitions = ["a-to-b", "b-to-a", "first-a-to-b", "first-b-to-a"];

    public static Dictionary<string, Observation> Schedule(
        IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Func<string, string, Observation> execute)
    {
        var results = new Dictionary<string, Observation>();
        foreach (var identity in new[] { "original", "a", "b" })
            foreach (var scenario in Cases)
                results[identity + "-" + scenario] = Ready(identity) ? Safe(identity, scenario) : new("skipped");
        foreach (var direction in Transitions)
            results[direction] = Ready("a") && Ready("b") ? Safe(direction, "transition") : new("skipped");
        return results;
        bool Ready(string identity) => native[identity + "-direct"].Status == "passed" && native[identity + "-referral"].Status == "passed";
        Observation Safe(string identity, string scenario)
        { try { return execute(identity, scenario); } catch { return new("failed", FailureKind: "fixture"); } }
    }
    public static Dictionary<string, Observation> Run(IReadOnlyDictionary<string, WindowsAuthenticatedDiagnostic.Observation> native,
        Action<Action> accountA, Action<Action> accountB)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var scopes = new Dictionary<string, Action<Action>> { ["original"] = action => action(), ["a"] = accountA, ["b"] = accountB };
        return Schedule(native, (identity, scenario) => scenario == "transition"
            ? Observe(scopes[identity.Contains("a-to-b") ? "a" : "b"], scenario,
                scopes[identity.Contains("a-to-b") ? "b" : "a"], identity.StartsWith("first-"))
            : Observe(scopes[identity], scenario));
    }

    private static Observation Observe(Action<Action> scope, string scenario, Action<Action>? second = null, bool firstAfterSwitch = false)
    {
        Fixture? fixture = null;
        string status = "failed";
        Exception? failure = null;
        try
        {
            // Server/key creation stays under original identity, before impersonation.
            RunPreparedCase(() => fixture = new Fixture(scenario == "untrusted-target", scenario == "mixed-referral", scenario == "isolation", scenario.EndsWith("concurrent")),
                scenario == "transition" ? action => action() : scope,
                () => { if (scenario == "transition") Transition(fixture!, scope, second!, firstAfterSwitch); else Execute(fixture!, scenario); });
            status = "passed";
        }
        catch (Exception error) { failure = error; }
        finally
        {
            try { fixture?.Dispose(); }
            catch (Exception error) { failure = PreserveOriginalFailure(failure, error); status = "failed"; }
        }
        // Teardown joins server tasks. Recheck after it so a late duplicate cannot
        // leave a passing status and then disappear behind a report-schema failure.
        if (status == "passed" && scenario.EndsWith("concurrent") && fixture is not null &&
            (fixture.ManagedAttempts != 2 || fixture.Target.Searches != 2 || !fixture.Timeline!.ExactOperations()))
        {
            failure = new DiagnosticAssertionException("concurrent-counts");
            status = "failed";
        }
        var (kind, code) = failure is null ? ("none", 0) : Describe(failure);
        return new(status, fixture?.Checks ?? 0, fixture?.Source.Binds ?? 0,
            fixture?.Target.Connections ?? 0, fixture?.Target.TlsHandshakes ?? 0,
            fixture?.Target.Binds ?? 0, fixture?.Target.Searches ?? 0,
            fixture?.Target.AnonymousBinds ?? 0, fixture?.Target.SaslBinds ?? 0,
            fixture?.Target.Closed ?? 0, fixture?.ManagedAttempts ?? 0,
            fixture?.BaselineCredentialed ?? 0, fixture?.PooledCredentialed ?? 0,
            fixture?.Cleanup ?? false, kind, code, fixture?.ObservedFailureKind ?? "none", fixture?.ObservedFailureCode ?? 0,
            fixture?.CleanupDetail.Mask ?? 0, fixture?.CleanupDetail.LeaseCode ?? 0, fixture?.CleanupDetail.KeyCode ?? 0,
            fixture?.CleanupDetail.OtherCode ?? 0, fixture?.CleanupDetail.SourceCode ?? 0, fixture?.CleanupDetail.TargetCode ?? 0,
            fixture?.CleanupDetail.PoolDelta ?? 0, fixture?.Source.Abandons ?? 0, fixture?.Target.Abandons ?? 0,
            fixture?.Target.FirstRecords.Count(x => x == "TLS handshake") ?? 0,
            fixture?.Target.FirstRecords.Count(x => x == "LDAP BER") ?? 0, FailurePoint(failure, fixture is null), fixture?.Target.RejectedTlsProbes ?? 0,
            fixture?.Concurrent.Ready ?? 0, fixture?.Concurrent.Starts ?? 0,
            fixture?.Overlap?.Arrivals ?? 0, fixture?.Overlap?.Timeouts ?? 0,
            fixture?.Timeline?.Snapshot() ?? "", fixture?.Timeline?.Dropped ?? 0);
    }
    private sealed class DiagnosticAssertionException(string point) : Exception
    { internal string Point { get; } = point; }
    private static string FailurePoint(Exception? failure, bool setup)
    {
        if (failure is null) return "none";
        if (failure is AggregateException aggregate) failure = aggregate.Flatten().InnerExceptions.FirstOrDefault() ?? failure;
        if (failure is DiagnosticAssertionException assertion) return assertion.Point;
        if (failure is ObservedResponseException) return "native-response";
        if (failure is LdapException or DirectoryOperationException) return "native-operation";
        return setup ? "setup" : "other";
    }
    internal static void RunPreparedCase(Action prepare, Action<Action> scope, Action operation)
    {
        prepare(); // Endpoint creation and owned-key loading must finish before impersonation.
        scope(operation);
    }
    internal static Exception PreserveConstructionFailure(Exception original, params Action[] cleanup)
    {
        foreach (var action in cleanup) { try { action(); } catch { /* Preserve the construction error; no success claim. */ } }
        return original;
    }
    internal static Exception PreserveOriginalFailure(Exception? original, Exception cleanup) => original ?? cleanup;
    private sealed class ObservedResponseException(ResultCode result) : Exception
    { internal ResultCode Result { get; } = result; }
    private static (string, int) Describe(Exception error) => error switch
    {
        ObservedResponseException response => ("response", (int)response.Result),
        LdapException ldap => ("ldap", ldap.ErrorCode),
        DirectoryOperationException operation => ("directory", operation.Response is null ? operation.HResult : (int)operation.Response.ResultCode),
        _ => ("fixture", error.HResult),
    };
    private static void Execute(Fixture f, string scenario)
    {
        switch (scenario)
        {
            case "isolation": Isolation(f); break;
            case "concurrent": Concurrent(f, false); break;
            case "unpooled-concurrent": Concurrent(f, true); break;
            case "capacity": Capacity(f); break;
            case "generation": Generation(f); break;
            case "failed-bind": FailedBind(f); break;
            case "primary-disconnect": Disconnect(f, f.Source); break;
            case "target-disconnect": Disconnect(f, f.Target); break;
            case "target-bind-rejection": RejectedTarget(f); break;
            case "untrusted-target": UntrustedTarget(f); break;
            case "mixed-referral": MixedReferral(f); break;
            default: throw new InvalidOperationException("Unknown pool scenario.");
        }
    }
    private static void Isolation(Fixture f)
    {
        var options = f.Options();
        var initial = f.Acquire(options); f.Read(initial); var old = initial.Connection; initial.Dispose();
        var other = f.Acquire(f.Options(identity: WindowsReferralEndpoint.SecondIdentity));
        f.Require(!ReferenceEquals(old, other.Connection)); f.Read(other, WindowsReferralEndpoint.SecondIdentity); other.Dispose();
        var timeout = f.Acquire(f.Options(seconds: 7)); f.Require(!ReferenceEquals(old, timeout.Connection)); f.Read(timeout); timeout.Dispose();
        var port = f.Acquire(f.Options(endpoint: f.OtherSource)); f.Require(!ReferenceEquals(old, port.Connection)); f.Read(port); port.Dispose();
        var noReferral = f.Acquire(options, none: true); f.Require(!ReferenceEquals(old, noReferral.Connection)); noReferral.Dispose();
        int binds = f.Source.Binds;
        var again = f.Acquire(options); f.Require(ReferenceEquals(old, again.Connection) && f.Source.Binds == binds); f.Read(again);
        f.Require(f.Target.AnonymousBinds == 0 && f.Target.SaslBinds == 0);
    }
    private static void FailedBind(Fixture f)
    {
        var initial = f.Acquire(f.Options()); f.Read(initial); var old = initial.Connection; initial.Dispose();
        int binds = f.Source.Binds, total = LdapConnectionProvider.Snapshot.Total;
        Exception? error = null;
        try { f.Acquire(f.Options(password: "incorrect synthetic password")); } catch (Exception e) { error = e; }
        if (error is not null) (f.ObservedFailureKind, f.ObservedFailureCode) = Describe(error);
        f.Require(error is LdapException { ErrorCode: 49 });
        f.Require(f.Source.Binds == binds + 1 && LdapConnectionProvider.Snapshot.Total == total);
        var again = f.Acquire(f.Options()); f.Require(ReferenceEquals(old, again.Connection)); f.Read(again);
    }
    private static void Concurrent(Fixture f, bool unpooled)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        Func<int, SearchResponse> send;
        if (unpooled)
        {
            // Same factory/options/referrals and explicit bind as the pool's factory,
            // but no Session, pool lookup, key, generation, or lease on this path.
            var raw = new[] { f.Raw(), f.Raw() };
            f.Require(!ReferenceEquals(raw[0], raw[1]));
            send = index => f.SendCorrelated(raw[index], index + 1);
        }
        else
        {
            var leases = f.Batch(f.Options(), 2);
            f.Require(!ReferenceEquals(leases[0].Connection, leases[1].Connection));
            send = index => leases[index].Execute(connection => f.SendCorrelated(connection, index + 1));
        }
        f.Overlap = new WindowsDiagnosticOverlap(f.Timeline!, TimeSpan.FromSeconds(3));
        f.Target.BeforeCorrelatedSearchResponse = f.Overlap.Arrive;
        using var caller = WindowsIdentity.GetCurrent();
        string? sid = caller.User?.Value;
        f.Require(sid is not null);
        f.Concurrent.Run(index =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var current = WindowsIdentity.GetCurrent();
            f.Require(current.User?.Value == sid, "ambient-identity");
            ValidateResponse(send(index), WindowsReferralEndpoint.FirstIdentity);
        });
        f.Target.BeforeCorrelatedSearchResponse = null;
        f.Require(f.Concurrent.Ready == 2 && f.Concurrent.Starts == 2 && f.Overlap.Arrivals == 2 &&
            f.Overlap.Timeouts == 0 && f.ManagedAttempts == 2 && f.Target.Searches == 2 &&
            f.Source.Binds == 2 && f.Timeline!.ExactOperations(), "concurrent-counts");
    }
    private static void Capacity(Fixture f)
    {
        var leases = f.Batch(f.Options(), 8);
        f.Require(leases.Select(x => x.Connection).Distinct().Count() == 8);
        int binds = f.Source.Binds;
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        Exception? error = null;
        try { f.Acquire(f.Options(), cancellation: cancel.Token); } catch (Exception e) { error = e; }
        f.Require(error is OperationCanceledException && f.Source.Binds == binds);
        f.Require(LdapConnectionProvider.Snapshot.Waiting == 0);
        var old = leases[0].Connection; leases[0].Dispose();
        var admitted = f.Acquire(f.Options()); f.Require(ReferenceEquals(old, admitted.Connection)); f.Read(admitted);
        f.Require(f.Source.Binds == binds);
    }
    private static void Generation(Fixture f)
    {
        var old = f.Acquire(f.Options()); f.Read(old); var connection = old.Connection;
        long generation = LdapConnectionProvider.NewGeneration();
        var fresh = f.Acquire(f.Options(), fresh: true, minimum: generation);
        f.Require(!ReferenceEquals(connection, fresh.Connection)); f.Read(fresh);
        old.Dispose();
        var after = f.Acquire(f.Options(), minimum: generation);
        f.Require(!ReferenceEquals(connection, after.Connection) && !ReferenceEquals(fresh.Connection, after.Connection)); f.Read(after);
        f.Require(f.Source.Binds == 3);
    }
    private static void Disconnect(Fixture f, WindowsReferralEndpoint endpoint)
    {
        var failed = f.Acquire(f.Options()); f.Read(failed); var old = failed.Connection;
        endpoint.DisconnectOnSearch = true;
        int attempts = f.ManagedAttempts;
        var error = f.CaptureRead(failed);
        f.Require(error is LdapException or DirectoryOperationException);
        f.Require(error is not null && LdapConnectionProvider.IsConnectionFailure(error));
        f.Require(f.ManagedAttempts == attempts + 1); // Native reconnects are observed, not called managed replay.
        failed.Dispose(); endpoint.DisconnectOnSearch = false;
        int binds = f.Source.Binds;
        var replacement = f.Acquire(f.Options());
        f.Require(!ReferenceEquals(old, replacement.Connection) && f.Source.Binds == binds + 1); f.Read(replacement);
    }
    private static void RejectedTarget(Fixture f)
    {
        f.Target.RejectBinds = true;
        var lease = f.Acquire(f.Options()); int attempts = f.ManagedAttempts;
        var error = f.CaptureRead(lease);
        f.Require(error is not null);
        f.Require(f.ManagedAttempts == attempts + 1);
        f.Require(f.Target.CredentialedSimpleBinds > 0 && f.Target.AnonymousBinds == 0 && f.Target.SaslBinds == 0 && f.Target.Searches == 0);
        f.Target.RejectBinds = false;
    }
    private static void UntrustedTarget(Fixture f)
    {
        var lease = f.Acquire(f.Options()); int attempts = f.ManagedAttempts;
        var error = f.CaptureRead(lease);
        f.Require(error is not null);
        f.Require(f.ManagedAttempts == attempts + 1);
        f.Require(error is LdapException or DirectoryOperationException or ObservedResponseException);
        f.Require(f.Source.Binds == 1 && f.Target.Connections > 0 && f.Target.Binds == 0 && f.Target.Searches == 0);
        // Server-side TLS completion is not itself proof the client trusted the cert.
    }
    private static void MixedReferral(Fixture f)
    {
        using var raw = LdapConnectionFactory.Create(f.Options());
        LdapConnectionFactory.ConfigureReferralChasing(raw, ReferralChasingOption.External); raw.Bind();
        Exception? baseline = null;
        try { Read(raw, WindowsReferralEndpoint.FirstIdentity); } catch (Exception e) { baseline = e; }
        f.BaselineCredentialed = f.Target.CredentialedSimpleBinds;
        int anonymous = f.Target.AnonymousBinds, sasl = f.Target.SaslBinds;
        LdapConnection? previous = null;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            int credentialedBefore = f.Target.CredentialedSimpleBinds, anonymousBefore = f.Target.AnonymousBinds;
            var lease = f.Acquire(f.Options());
            if (attempt == 1 && baseline is null) f.Require(ReferenceEquals(previous, lease.Connection));
            previous = lease.Connection;
            var candidate = f.CaptureRead(lease);
            f.Require(baseline is null or LdapException or DirectoryOperationException or ObservedResponseException);
            f.Require(candidate is null or LdapException or DirectoryOperationException or ObservedResponseException);
            f.Require((baseline is null) == (candidate is null));
            if (baseline is not null && candidate is not null) f.Require(Describe(baseline) == Describe(candidate));
            int credentialed = f.Target.CredentialedSimpleBinds - credentialedBefore;
            f.PooledCredentialed += credentialed;
            f.Require((f.BaselineCredentialed > 0) == (credentialed > 0));
            f.Require((anonymous > 0) == (f.Target.AnonymousBinds - anonymousBefore > 0));
            f.Require(sasl == 0 && f.Target.SaslBinds == 0);
            lease.Dispose();
        }
        f.Require(f.Target.RejectedTlsProbes == f.Target.FirstRecords.Count(x => x == "TLS handshake"));
        // Report any native explicit forwarding; never reconfigure auth or referrals.
    }
    private static void Transition(Fixture f, Action<Action> first, Action<Action> second, bool firstAfterSwitch)
    {
        foreach (var identity in new[] { WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.SecondIdentity })
        {
            LdapConnection? old = null;
            first(() => { var lease = f.Acquire(f.Options(identity)); old = lease.Connection;
                if (!firstAfterSwitch) f.Read(lease, identity); lease.Dispose(); });
            second(() => { var lease = f.Acquire(f.Options(identity)); f.Require(ReferenceEquals(old, lease.Connection));
                f.Read(lease, identity); lease.Dispose(); });
            first(() => { var lease = f.Acquire(f.Options(identity)); f.Require(ReferenceEquals(old, lease.Connection));
                f.Read(lease, identity); lease.Dispose(); });
        }
        f.Require(f.Source.Binds == 2 && f.Target.AnonymousBinds == 0 && f.Target.SaslBinds == 0);
    }
    private static SearchResponse ReadResponse(LdapConnection connection) =>
        (SearchResponse)connection.SendRequestTracked(new SearchRequest("CN=source", "(objectClass=*)", SearchScope.Base, "description"));
    private static string Read(LdapConnection connection, string identity) => ValidateResponse(ReadResponse(connection), identity);
    private static string ValidateResponse(SearchResponse response, string identity)
    {
        // Assertions occur OUTSIDE the provider operation. An unresolved response
        // must not become an invented native failure that makes eviction pass.
        if (response.ResultCode != ResultCode.Success) throw new ObservedResponseException(response.ResultCode);
        if (response.Entries.Count != 1 || response.Entries[0].Attributes["description"]?[0] is not string actual)
            throw new DiagnosticAssertionException("search-shape");
        if (actual != identity) throw new DiagnosticAssertionException("ldap-identity");
        return actual;
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly WindowsReferralEndpoint Target, Source;
        internal readonly WindowsReferralEndpoint? OtherSource;
        private readonly List<LdapConnectionProvider.Session> sessions = [];
        private readonly int initialTotal = LdapConnectionProvider.Snapshot.Total;
        private readonly Dictionary<LdapConnectionProvider.ConnectionKey, (LdapConnectionOptions Options, bool None)> keys = [];
        internal int Checks, ManagedAttempts, BaselineCredentialed, PooledCredentialed;
        internal bool Cleanup;
        internal readonly WindowsDiagnosticConcurrent Concurrent = new();
        internal readonly WindowsDiagnosticTimeline? Timeline;
        internal WindowsDiagnosticOverlap? Overlap;
        private readonly List<LdapConnection> rawConnections = [];
        internal readonly WindowsDiagnosticCleanup CleanupDetail = new();
        internal string ObservedFailureKind = "none";
        internal int ObservedFailureCode;
        internal Fixture(bool untrusted, bool mixed, bool isolation, bool concurrent)
        {
            if (concurrent) Timeline = new WindowsDiagnosticTimeline();
            Target = new WindowsReferralEndpoint(tls: !mixed, untrustedOwnedCertificate: untrusted, rejectTlsOnPlaintext: mixed) { Timeline = Timeline, TimelineRole = "target" };
            try
            {
                Source = new WindowsReferralEndpoint(tls: true) { ReferralUrl = $"{(mixed ? "ldap" : "ldaps")}://127.0.0.1:{Target.Port}/CN=target??base?(objectClass=*)" };
                Source.Timeline = Timeline; Source.TimelineRole = "source";
                if (isolation) OtherSource = new WindowsReferralEndpoint(tls: true) { ReferralUrl = Source.ReferralUrl };
            }
            catch (Exception original)
            {
                PreserveConstructionFailure(original,
                    () => Source?.DisposeAsync().AsTask().GetAwaiter().GetResult(),
                    () => Target.DisposeAsync().AsTask().GetAwaiter().GetResult());
                throw;
            }
        }
        internal LdapConnectionOptions Options(string identity = WindowsReferralEndpoint.FirstIdentity,
            string password = WindowsReferralEndpoint.Password, int seconds = 5, WindowsReferralEndpoint? endpoint = null) => new()
        { Host = "127.0.0.1", Port = (endpoint ?? Source).Port, UseSsl = true, AuthenticationType = AuthType.Basic,
            BindDn = identity, BindPassword = password, Timeout = TimeSpan.FromSeconds(seconds) };
        internal void Require(bool condition, string point = "assertion") { if (!condition) throw new DiagnosticAssertionException(point); Interlocked.Increment(ref Checks); }
        internal LdapConnectionProvider.Session Acquire(LdapConnectionOptions options, bool none = false, bool fresh = false,
            long minimum = 0, CancellationToken cancellation = default)
        {
            var lease = none ? LdapConnectionProvider.Acquire(options, cancellation, preferFresh: fresh, minimumGeneration: minimum)
                : LdapConnectionProvider.AcquireWindowsReferralDiagnostic(options, cancellationToken: cancellation, preferFresh: fresh, minimumGeneration: minimum)[0];
            sessions.Add(lease); keys[LdapConnectionProvider.ConnectionKey.Create(options, none ? ReferralChasingOption.None : ReferralChasingOption.External)] = (options, none);
            return lease;
        }
        internal LdapConnectionProvider.Session[] Batch(LdapConnectionOptions options, int count)
        {
            var leases = LdapConnectionProvider.AcquireWindowsReferralDiagnostic(options, count);
            sessions.AddRange(leases); keys[LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.External)] = (options, false);
            return leases;
        }
        internal LdapConnection Raw()
        {
            var raw = LdapConnectionFactory.Create(Options());
            rawConnections.Add(raw); // Own before configure/bind, including partial failures.
            LdapConnectionFactory.ConfigureReferralChasing(raw, ReferralChasingOption.External);
            raw.Bind();
            return raw;
        }
        internal SearchResponse SendCorrelated(LdapConnection connection, int operation)
        {
            Interlocked.Increment(ref ManagedAttempts);
            Timeline!.Add("client", 0, 0, operation, "native-enter");
            try
            {
                var response = (SearchResponse)connection.SendRequestTracked(new SearchRequest(
                    WindowsDiagnosticTimeline.BaseDn(operation), "(objectClass=*)", SearchScope.Base, "description"));
                Timeline.Add("client", 0, 0, operation, "native-exit");
                return response;
            }
            catch { Timeline.Add("client", 0, 0, operation, "native-error"); throw; }
        }
        internal void Read(LdapConnectionProvider.Session lease, string identity = WindowsReferralEndpoint.FirstIdentity)
        {
            var response = lease.Execute(connection => { Interlocked.Increment(ref ManagedAttempts); return ReadResponse(connection); });
            ValidateResponse(response, identity);
        }
        internal Exception? CaptureRead(LdapConnectionProvider.Session lease)
        { try { Read(lease); return null; } catch (Exception error) { (ObservedFailureKind, ObservedFailureCode) = Describe(error); return error; } }
        public void Dispose()
        {
            Source.DisconnectOnSearch = Target.DisconnectOnSearch = false;
            Target.RejectBinds = false; Target.BeforeSearchResponse = null; Target.BeforeCorrelatedSearchResponse = null;
            foreach (var raw in rawConnections) CleanupDetail.Attempt(1, raw.Dispose);
            foreach (var lease in sessions) CleanupDetail.Attempt(1, () => { lease.Invalidate(); lease.Dispose(); });
            // Retire each exact idle key via existing provider freshness semantics.
            // Cleanup binds are explicit and included in primary counters; never replay a read.
            foreach (var item in keys.Values)
            {
                CleanupDetail.Attempt(2, () =>
                {
                    using var cleanup = item.None ? LdapConnectionProvider.Acquire(item.Options, preferFresh: true)
                        : LdapConnectionProvider.AcquireWindowsReferralDiagnostic(item.Options, preferFresh: true)[0];
                    cleanup.Invalidate();
                });
            }
            CleanupDetail.Attempt(4, () => OtherSource?.DisposeAsync().AsTask().GetAwaiter().GetResult());
            CleanupDetail.Attempt(8, () => Source.DisposeAsync().AsTask().GetAwaiter().GetResult());
            CleanupDetail.Attempt(16, () => Target.DisposeAsync().AsTask().GetAwaiter().GetResult());
            CleanupDetail.CheckPool(initialTotal, LdapConnectionProvider.Snapshot.Total);
            Cleanup = CleanupDetail.Mask == 0;
            if (!Cleanup) throw new DiagnosticAssertionException("cleanup");
        }
    }
}
