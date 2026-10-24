using System.DirectoryServices.Protocols;
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
}
