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
            Assert.Equal(34, pool.Count);
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
    private sealed class SyntheticFailure : Exception
    { internal SyntheticFailure(int code) { HResult = code; } }
}
