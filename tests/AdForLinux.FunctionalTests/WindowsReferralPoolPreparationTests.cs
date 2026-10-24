using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

public sealed class WindowsReferralPoolPreparationTests
{
    private static LdapConnectionOptions Options(string host = "127.0.0.1", bool ssl = true, bool startTls = false,
        bool skip = false, AuthType auth = AuthType.Basic, string? dn = "synthetic", string? password = "synthetic",
        bool signing = false, bool sealing = false, int port = 12345) => new()
        { Host = host, Port = port, UseSsl = ssl, UseStartTls = startTls, SkipCertificateCheck = skip,
            AuthenticationType = auth, BindDn = dn, BindPassword = password, Signing = signing, Sealing = sealing };
    [Fact]
    public void Candidate_configuration_is_narrow_and_does_not_change_default_policy()
    {
        var options = Options();
        Assert.True(LdapConnectionProvider.IsWindowsReferralDiagnosticConfiguration(options));
        foreach (var excluded in new[] { Options(host: "localhost"), Options(host: "::1"), Options(host: "192.0.2.1"),
            Options(ssl: false), Options(startTls: true), Options(skip: true), Options(auth: AuthType.Negotiate),
            Options(auth: AuthType.Kerberos), Options(auth: AuthType.Anonymous), Options(dn: null), Options(password: ""),
            Options(signing: true), Options(sealing: true), Options(port: 0), Options(port: 65536) })
            Assert.False(LdapConnectionProvider.IsWindowsReferralDiagnosticConfiguration(excluded));
        Assert.Equal(OperatingSystem.IsLinux(), LdapConnectionProvider.CanReuse(options, ReferralChasingOption.External));
        Assert.False(LdapConnectionProvider.CanReuse(Options(auth: AuthType.Negotiate), ReferralChasingOption.External));
    }
    [Fact]
    public void Pool_scheduler_keeps_each_native_dependency_and_anonymous_adverse_outcome_separate()
    {
        foreach (var failure in new[] { "", "original-direct", "a-direct", "b-referral", "anonymous-direct" })
        {
            var native = WindowsAuthenticatedDiagnostic.Schedule((identity, stage) =>
                new(identity + "-" + stage == failure ? "failed" : "passed", 0, 0, 0, 0, 0, 0));
            var calls = new List<string>();
            var pool = WindowsReferralPoolDiagnostic.Schedule(native, (identity, scenario) =>
            { calls.Add(identity + "-" + scenario); return new("passed"); });
            Assert.Equal(37, pool.Count);
            if (failure == "a-direct") { Assert.DoesNotContain(calls, n => n.StartsWith("a-") || n.Contains("to-a") || n.Contains("a-to")); Assert.Equal("passed", pool["b-isolation"].Status); }
            if (failure == "b-referral") Assert.Equal("skipped", pool["first-a-to-b"].Status);
            if (failure == "original-direct") Assert.Equal("passed", pool["a-to-b"].Status);
            var report = WindowsDiagnosticReport.Create(native, pool);
            if (failure == "anonymous-direct") { Assert.Equal("passed", report.Supported); Assert.Equal("failed", report.Adverse); Assert.False(report.AllPassed); }
            if (failure == "") Assert.True(report.AllPassed);
        }
    }
    [Fact]
    public void Cleanup_attempts_all_categories_and_reports_pool_delta_without_replacing_operation_error()
    {
        var cleanup = new WindowsDiagnosticCleanup();
        var attempted = new List<int>();
        foreach (int bit in new[] { 1, 2, 4, 8, 16 })
            cleanup.Attempt(bit, () => { attempted.Add(bit); throw new SyntheticFailure(-100 - bit); });
        cleanup.CheckPool(2, 3);
        Assert.Equal(new[] { 1, 2, 4, 8, 16 }, attempted);
        Assert.Equal(63, cleanup.Mask);
        Assert.Equal(-101, cleanup.LeaseCode); Assert.Equal(-102, cleanup.KeyCode);
        Assert.Equal(-104, cleanup.OtherCode); Assert.Equal(-108, cleanup.SourceCode); Assert.Equal(-116, cleanup.TargetCode);
        Assert.Equal(1, cleanup.PoolDelta);
        var original = new UnauthorizedAccessException();
        var disposal = new InvalidOperationException();
        Assert.Same(original, WindowsReferralPoolDiagnostic.PreserveOriginalFailure(original, disposal));
        Assert.Same(disposal, WindowsReferralPoolDiagnostic.PreserveOriginalFailure(null, disposal));
    }
    [Fact]
    public void Successful_cleanup_has_no_failure_bits_or_codes()
    {
        var cleanup = new WindowsDiagnosticCleanup();
        foreach (int bit in new[] { 1, 2, 4, 8, 16 }) cleanup.Attempt(bit, () => { });
        cleanup.CheckPool(0, 0);
        Assert.Equal(0, cleanup.Mask); Assert.Equal(0, cleanup.PoolDelta);
        Assert.Equal(0, cleanup.LeaseCode); Assert.Equal(0, cleanup.KeyCode);
        Assert.Equal(0, cleanup.OtherCode); Assert.Equal(0, cleanup.SourceCode); Assert.Equal(0, cleanup.TargetCode);
    }
    [Fact]
    public void Abandon_is_a_primitive_message_id_not_a_constructed_operation()
    {
        var valid = new AsnReader(new byte[] { 0x50, 0x01, 0x07 }, AsnEncodingRules.BER);
        Assert.True(WindowsReferralEndpoint.TryConsumeAbandon(valid));
        Assert.False(valid.HasData);
        var search = new AsnReader(new byte[] { 0x63, 0x00 }, AsnEncodingRules.BER);
        Assert.False(WindowsReferralEndpoint.TryConsumeAbandon(search)); Assert.True(search.HasData);
        Assert.Throws<AsnContentException>(() => WindowsReferralEndpoint.TryConsumeAbandon(
            new AsnReader(new byte[] { 0x70, 0x03, 0x02, 0x01, 0x07 }, AsnEncodingRules.BER)));
        Assert.Throws<InvalidDataException>(() => WindowsReferralEndpoint.TryConsumeAbandon(
            new AsnReader(new byte[] { 0x50, 0x01, 0x00 }, AsnEncodingRules.BER)));
    }
    [Fact]
    public void All_endpoint_preparation_precedes_identity_scope_and_setup_errors_survive_cleanup()
    {
        bool impersonated = false;
        var events = new List<string>();
        WindowsReferralPoolDiagnostic.RunPreparedCase(
            () => { Assert.False(impersonated); events.Add("target"); events.Add("source"); events.Add("alternate"); },
            action => { impersonated = true; try { events.Add("scope"); action(); } finally { impersonated = false; } },
            () => { Assert.True(impersonated); events.Add("operation"); });
        Assert.Equal(new[] { "target", "source", "alternate", "scope", "operation" }, events);
        bool entered = false;
        Assert.Throws<UnauthorizedAccessException>(() => WindowsReferralPoolDiagnostic.RunPreparedCase(
            () => throw new UnauthorizedAccessException(), action => { entered = true; action(); }, () => { }));
        Assert.False(entered);
        var original = new UnauthorizedAccessException(); int cleanups = 0;
        Assert.Same(original, WindowsReferralPoolDiagnostic.PreserveConstructionFailure(original,
            () => { cleanups++; throw new InvalidOperationException(); },
            () => { cleanups++; throw new IOException(); }));
        Assert.Equal(2, cleanups);
    }
    [Fact]
    public void Only_designated_plaintext_control_rejects_a_TLS_handshake_prefix()
    {
        Assert.True(WindowsReferralEndpoint.ShouldRejectTlsProbe(true, false, 0x16));
        Assert.False(WindowsReferralEndpoint.ShouldRejectTlsProbe(false, false, 0x16));
        Assert.False(WindowsReferralEndpoint.ShouldRejectTlsProbe(true, true, 0x16));
        foreach (byte? prefix in new byte?[] { null, 0x30, 0x15, 0x01 })
            Assert.False(WindowsReferralEndpoint.ShouldRejectTlsProbe(true, false, prefix));
    }
    [Fact]
    public void Dedicated_workers_flow_context_overlap_and_join_before_return()
    {
        var context = new AsyncLocal<string> { Value = "synthetic-context" };
        var runner = new WindowsDiagnosticConcurrent();
        using var arrived = new CountdownEvent(2);
        var ids = new int[2]; int completed = 0;
        runner.Run(index =>
        {
            Assert.False(Thread.CurrentThread.IsThreadPoolThread);
            Assert.Equal("synthetic-context", context.Value);
            ids[index] = Environment.CurrentManagedThreadId;
            arrived.Signal();
            Assert.True(arrived.Wait(TimeSpan.FromSeconds(3)));
            Interlocked.Increment(ref completed);
        });
        Assert.NotEqual(ids[0], ids[1]);
        Assert.Equal(2, completed); Assert.Equal(2, runner.Ready); Assert.Equal(2, runner.Starts);
    }
    [Fact]
    public void Worker_failure_does_not_leave_the_other_operation_running()
    {
        var runner = new WindowsDiagnosticConcurrent();
        using var arrived = new CountdownEvent(2);
        int completed = 0;
        var error = Assert.Throws<AggregateException>(() => runner.Run(index =>
        {
            arrived.Signal();
            Assert.True(arrived.Wait(TimeSpan.FromSeconds(3)));
            if (index == 0) throw new SyntheticFailure(-123);
            Interlocked.Increment(ref completed);
        }));
        Assert.Contains(error.InnerExceptions, e => e is SyntheticFailure);
        Assert.Equal(1, completed); Assert.Equal(2, runner.Starts);
    }
    [Fact]
    public void Timeline_is_bounded_fixed_vocabulary_and_exact_synthetic_ids_only()
    {
        var trace = new WindowsDiagnosticTimeline();
        Assert.Throws<ArgumentException>(() => trace.Add("private-user", 0, 0, 0, "accept"));
        Assert.Throws<ArgumentException>(() => trace.Add("client", 0, 0, 0, "secret-payload"));
        Assert.Throws<ArgumentException>(() => trace.Add("client", 0, 0, 3, "native-enter"));
        for (int i = 0; i < WindowsDiagnosticTimeline.Limit + 2; i++) trace.Add("target", 1, 0, 0, "accept");
        Assert.Equal(WindowsDiagnosticTimeline.Limit, trace.Snapshot().Split(';').Length);
        Assert.Equal(2, trace.Dropped); Assert.False(trace.ExactOperations());
        for (int operation = 1; operation <= 2; operation++)
            Assert.Equal(operation, WindowsDiagnosticTimeline.Operation(System.Text.Encoding.UTF8.GetBytes(WindowsDiagnosticTimeline.BaseDn(operation))));
        Assert.Throws<InvalidDataException>(() => WindowsDiagnosticTimeline.Operation("CN=unexpected"u8.ToArray()));
    }
    private static WindowsDiagnosticTimeline OverlapTrace(bool duplicate = false, bool sharedSource = false, bool serialSource = false)
    {
        var trace = new WindowsDiagnosticTimeline();
        foreach (int operation in new[] { 1, 2 }) trace.Add("client", 0, 0, operation, "native-enter");
        foreach (int operation in serialSource ? Array.Empty<int>() : new[] { 1, 2 })
        {
            trace.Add("source", sharedSource ? 1 : operation, operation, operation, "search");
            trace.Add("source", sharedSource ? 1 : operation, operation, operation, "arrive");
        }
        foreach (int operation in new[] { 1, 2 })
        {
            if (serialSource)
            {
                trace.Add("source", operation, operation, operation, "search");
                trace.Add("source", operation, operation, operation, "arrive");
            }
            trace.Add("source", sharedSource ? 1 : operation, operation, operation, "release");
            trace.Add("source", sharedSource ? 1 : operation, operation, operation, "referral-send");
            // A shared sequential target connection is allowed; duplicate requests are not.
            trace.Add("target", 1, operation, duplicate ? 1 : operation, "search");
            trace.Add("target", 1, operation, operation, "response-send");
            trace.Add("client", 0, 0, operation, "native-exit");
        }
        return trace;
    }
    [Fact]
    public void Primary_overlap_allows_shared_target_but_rejects_duplicates_or_shared_primary()
    {
        Assert.True(OverlapTrace().ExactOperations());
        Assert.False(OverlapTrace(duplicate: true).ExactOperations());
        Assert.False(OverlapTrace(sharedSource: true).ExactOperations());
        Assert.False(OverlapTrace(serialSource: true).ExactOperations());
    }
    [Fact]
    public async Task Source_timeout_releases_response_without_erasing_failure_or_closing_connection()
    {
        var trace = new WindowsDiagnosticTimeline();
        var overlap = new WindowsDiagnosticOverlap(trace, TimeSpan.FromMilliseconds(20));
        int responses = 0;
        await overlap.Arrive(1, 1, 1); responses++;
        await overlap.Arrive(2, 2, 2); responses++;
        Assert.Equal(2, responses); Assert.Equal(2, overlap.Arrivals); Assert.Equal(1, overlap.Timeouts);
        var rows = trace.Snapshot().Split(';');
        Assert.Contains(rows, e => e.EndsWith(":1:timeout"));
        Assert.DoesNotContain(rows, e => e.EndsWith(":fault") || e.EndsWith(":close"));
        Assert.False(trace.ExactOperations());
    }
    [Fact]
    public async Task Overlapping_requests_release_without_timeout()
    {
        var overlap = new WindowsDiagnosticOverlap(new WindowsDiagnosticTimeline(), TimeSpan.FromSeconds(3));
        await Task.WhenAll(overlap.Arrive(1, 1, 1), overlap.Arrive(2, 2, 2));
        Assert.Equal(2, overlap.Arrivals); Assert.Equal(0, overlap.Timeouts);
    }
    [Fact]
    public void Unpooled_control_runs_even_when_pool_concurrency_fails()
    {
        var native = WindowsAuthenticatedDiagnostic.Schedule((_, _) => new("passed", 0, 0, 0, 0, 0, 0));
        var result = WindowsReferralPoolDiagnostic.Schedule(native, (_, scenario) => new(scenario == "concurrent" ? "failed" : "passed"));
        foreach (string identity in new[] { "original", "a", "b" })
        {
            Assert.Equal("failed", result[identity + "-concurrent"].Status);
            Assert.Equal("passed", result[identity + "-unpooled-concurrent"].Status);
        }
    }
    private sealed class SyntheticFailure : Exception
    { internal SyntheticFailure(int code) { HResult = code; } }
}
