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
        string FailureKind = "none", int FailureCode = 0, string ObservedFailureKind = "none", int ObservedFailureCode = 0);
    public static readonly string[] Cases = ["isolation", "concurrent", "capacity", "generation", "failed-bind",
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
        string status = "failed", kind = "none"; int code = 0;
        try
        {
            // Server/key creation stays under original identity, before impersonation.
            fixture = new Fixture(scenario == "untrusted-target", scenario == "mixed-referral");
            if (scenario == "transition") Transition(fixture, scope, second!, firstAfterSwitch);
            else scope(() => Execute(fixture, scenario));
            status = "passed";
        }
        catch (Exception error) { (kind, code) = Describe(error); }
        finally
        {
            try { fixture?.Dispose(); }
            catch (Exception error) { status = "failed"; (kind, code) = Describe(error); }
        }
        return new(status, fixture?.Checks ?? 0, fixture?.Source.Binds ?? 0,
            fixture?.Target.Connections ?? 0, fixture?.Target.TlsHandshakes ?? 0,
            fixture?.Target.Binds ?? 0, fixture?.Target.Searches ?? 0,
            fixture?.Target.AnonymousBinds ?? 0, fixture?.Target.SaslBinds ?? 0,
            fixture?.Target.Closed ?? 0, fixture?.ManagedAttempts ?? 0,
            fixture?.BaselineCredentialed ?? 0, fixture?.PooledCredentialed ?? 0,
            fixture?.Cleanup ?? false, kind, code, fixture?.ObservedFailureKind ?? "none", fixture?.ObservedFailureCode ?? 0);
    }
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
            case "concurrent": Concurrent(f); break;
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
        f.OtherSource = new WindowsReferralEndpoint(tls: true) { ReferralUrl = f.Source.ReferralUrl };
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
    private static void Concurrent(Fixture f)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var leases = f.Batch(f.Options(), 2);
        f.Require(!ReferenceEquals(leases[0].Connection, leases[1].Connection));
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrived = 0;
        f.Target.BeforeSearchResponse = async () =>
        {
            if (Interlocked.Increment(ref arrived) == 2) both.TrySetResult();
            await both.Task.WaitAsync(TimeSpan.FromSeconds(3));
        };
        using var caller = WindowsIdentity.GetCurrent();
        string? sid = caller.User?.Value;
        f.Require(sid is not null);
        // ExecutionContext flows into Task.Run. Assert actual identity in each task;
        // wait for BOTH before returning from the existing synchronous token scope.
        Task.WaitAll(leases.Select(lease => Task.Run(() =>
        {
            using var current = WindowsIdentity.GetCurrent();
            f.Require(current.User?.Value == sid);
            f.Read(lease);
        })).ToArray());
        f.Target.BeforeSearchResponse = null;
        f.Require(arrived == 2 && f.Target.Searches == 2 && f.Source.Binds == 2);
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
        if (response.Entries.Count != 1 ||
            response.Entries[0].Attributes["description"]?[0] is not string actual || actual != identity)
            throw new InvalidOperationException("Synthetic LDAP identity mismatch.");
        return actual;
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly WindowsReferralEndpoint Target, Source;
        internal WindowsReferralEndpoint? OtherSource;
        private readonly List<LdapConnectionProvider.Session> sessions = [];
        private readonly int initialTotal = LdapConnectionProvider.Snapshot.Total;
        private readonly Dictionary<LdapConnectionProvider.ConnectionKey, (LdapConnectionOptions Options, bool None)> keys = [];
        internal int Checks, ManagedAttempts, BaselineCredentialed, PooledCredentialed;
        internal bool Cleanup;
        internal string ObservedFailureKind = "none";
        internal int ObservedFailureCode;
        internal Fixture(bool untrusted, bool mixed)
        {
            Target = new WindowsReferralEndpoint(tls: !mixed, untrustedOwnedCertificate: untrusted);
            try { Source = new WindowsReferralEndpoint(tls: true) { ReferralUrl = $"{(mixed ? "ldap" : "ldaps")}://127.0.0.1:{Target.Port}/CN=target??base?(objectClass=*)" }; }
            catch { Target.DisposeAsync().AsTask().GetAwaiter().GetResult(); throw; }
        }
        internal LdapConnectionOptions Options(string identity = WindowsReferralEndpoint.FirstIdentity,
            string password = WindowsReferralEndpoint.Password, int seconds = 5, WindowsReferralEndpoint? endpoint = null) => new()
        { Host = "127.0.0.1", Port = (endpoint ?? Source).Port, UseSsl = true, AuthenticationType = AuthType.Basic,
            BindDn = identity, BindPassword = password, Timeout = TimeSpan.FromSeconds(seconds) };
        internal void Require(bool condition) { if (!condition) throw new InvalidOperationException("Pool diagnostic assertion failed."); Interlocked.Increment(ref Checks); }
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
        internal void Read(LdapConnectionProvider.Session lease, string identity = WindowsReferralEndpoint.FirstIdentity)
        {
            var response = lease.Execute(connection => { Interlocked.Increment(ref ManagedAttempts); return ReadResponse(connection); });
            ValidateResponse(response, identity);
        }
        internal Exception? CaptureRead(LdapConnectionProvider.Session lease)
        { try { Read(lease); return null; } catch (Exception error) { (ObservedFailureKind, ObservedFailureCode) = Describe(error); return error; } }
        public void Dispose()
        {
            bool failed = false;
            Source.DisconnectOnSearch = Target.DisconnectOnSearch = false;
            Target.RejectBinds = false; Target.BeforeSearchResponse = null;
            foreach (var lease in sessions) { try { lease.Invalidate(); lease.Dispose(); } catch { failed = true; } }
            // Retire each exact idle key via existing provider freshness semantics.
            // Cleanup binds are explicit and included in primary counters; never replay a read.
            foreach (var item in keys.Values)
            {
                try
                {
                    using var cleanup = item.None ? LdapConnectionProvider.Acquire(item.Options, preferFresh: true)
                        : LdapConnectionProvider.AcquireWindowsReferralDiagnostic(item.Options, preferFresh: true)[0];
                    cleanup.Invalidate();
                }
                catch { failed = true; }
            }
            foreach (var endpoint in new[] { OtherSource, Source, Target })
                try { endpoint?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { failed = true; }
            if (LdapConnectionProvider.Snapshot.Total != initialTotal) failed = true;
            Cleanup = !failed;
            if (failed) throw new InvalidOperationException("Pool fixture cleanup failed.");
        }
    }
}
