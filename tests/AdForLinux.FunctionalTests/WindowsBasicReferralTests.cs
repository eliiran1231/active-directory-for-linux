using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Xunit.Abstractions;
using ReferralChasingOption = AdForLinux.DirectoryServices.ReferralChasingOption;

namespace AdForLinux.FunctionalTests;

public sealed class WindowsReferralFactAttribute : FactAttribute
{
    public WindowsReferralFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires native WinLDAP on Windows; not an offline mock.";
    }
}

// Deliberately excluded from the offline allowlist. The dedicated hosted Windows
// job runs this exact class against loopback endpoints, never a configured domain.
public sealed class WindowsReferralDiagnosticTheoryAttribute : TheoryAttribute
{
    public WindowsReferralDiagnosticTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") is null)
            Skip = "Opt-in hosted certificate-trust diagnostic only.";
    }
}

public sealed class WindowsBasicReferralTests(ITestOutputHelper output)
{
    private int certificateCallbacks;
    private bool diagnosticPrimaryCallback;
    private string testHost = "127.0.0.1";
    private LdapConnectionOptions Options(WindowsReferralEndpoint source, string identity, bool tls = true) => new()
    {
        Host = testHost, Port = source.Port, UseSsl = tls,
        // Existing per-connection test option, scoped to this ephemeral loopback
        // certificate. The opt-in diagnostic uses normal validation by default.
        SkipCertificateCheck = tls && (diagnosticPrimaryCallback || Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") is null), BindDn = identity, BindPassword = WindowsReferralEndpoint.Password,
        Timeout = TimeSpan.FromSeconds(5),
    };

    private LdapConnection Open(LdapConnectionOptions options)
        => LdapConnectionFactory.ConfigureOwned(LdapConnectionFactory.Create(options), connection =>
        {
            LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.External);
            if (options.SkipCertificateCheck)
            {
                var existing = connection.SessionOptions.VerifyServerCertificate;
                connection.SessionOptions.VerifyServerCertificate = (owner, certificate) =>
                {
                    Interlocked.Increment(ref certificateCallbacks);
                    return existing(owner, certificate);
                };
            }
            connection.Bind();
        });

    private static string Read(LdapConnection connection)
    {
        var response = (SearchResponse)connection.SendRequest(new SearchRequest("CN=source", "(objectClass=*)",
            SearchScope.Base, "description"));
        Assert.True(response.Entries.Count == 1,
            $"Native response: result={response.ResultCode}, entries={response.Entries.Count}, referrals={response.Referral.Length}, references={response.References.Count}.");
        var entry = response.Entries[0];
        return Assert.IsType<string>(entry.Attributes["description"][0]);
    }

    [WindowsReferralFact]
    public Task Direct_target_tls_under_original_identity()
        => CheckDirectTargetTls(anonymous: false);

    [WindowsReferralFact]
    public Task Direct_target_tls_under_anonymous_impersonation()
        => CheckDirectTargetTls(anonymous: true);

    private async Task CheckDirectTargetTls(bool anonymous)
    {
        // Independent direct controls, not referral or pool-safety assertions.
        // Warm the same client/callback path before impersonation: anonymous
        // threads cannot load assemblies from the runner workspace.
        int callbacks = 0;
        string phase = "initialization";
        Action CreateRead(WindowsReferralEndpoint endpoint)
        {
            var pin = endpoint.PublicCertificateBytes;
            var options = new LdapConnectionOptions
            {
                Host = "127.0.0.1", Port = endpoint.Port, UseSsl = true,
                BindDn = WindowsReferralEndpoint.FirstIdentity,
                BindPassword = WindowsReferralEndpoint.Password,
                Timeout = TimeSpan.FromSeconds(5),
            };
            return () =>
            {
                phase = "create";
                using var connection = LdapConnectionFactory.Create(options);
                // Exact DER pin on this client only; no trust-store changes and
                // no callback attached to native referral children.
                connection.SessionOptions.VerifyServerCertificate = (_, presented) =>
                {
                    Interlocked.Increment(ref callbacks);
                    return presented is not null && pin.AsSpan().SequenceEqual(presented.GetRawCertData());
                };
                phase = "bind";
                connection.Bind();
                phase = "search";
                Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(connection));
                phase = "complete";
            };
        }
        var warmup = new WindowsReferralEndpoint(tls: true);
        using (var warmupReport = new FinalReport(() => output.WriteLine(
            $"Direct warmup: phase={phase}; TLS={warmup.TlsHandshakes}; binds={warmup.Binds}; " +
            $"searches={warmup.Searches}; pin callbacks={callbacks}; failures={string.Join(";", warmup.TransportFailures)}.")))
        {
            await using var warmupLifetime = warmup;
            CreateRead(warmup)();
        }
        callbacks = 0;
        var target = new WindowsReferralEndpoint(tls: true);
        using var report = new FinalReport(() => output.WriteLine(
            $"Direct target: ambient={(anonymous ? "anonymous" : "original")}; phase={phase}; " +
            $"connections={target.Connections}; closed={target.Closed}; TLS={target.TlsHandshakes}; " +
            $"binds={target.Binds}; searches={target.Searches}; credentialed={target.CredentialedSimpleBinds}; " +
            $"anonymous binds={target.AnonymousBinds}; SASL={target.SaslBinds}; pin callbacks={callbacks}; " +
            $"first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}."));
        await using var lifetime = target;
        var read = CreateRead(target);
        phase = "enter identity scope";
        if (anonymous) AsAnonymous(read);
        else read();
        Assert.Equal(1, target.Connections);
        Assert.Equal(1, target.TlsHandshakes);
        Assert.Equal(1, target.Binds);
        Assert.Equal(1, target.CredentialedSimpleBinds);
        Assert.Equal(1, target.Searches);
        Assert.Equal(0, target.AnonymousBinds);
        Assert.Equal(0, target.SaslBinds);
        Assert.True(callbacks > 0, "The direct client must validate the exact test certificate.");
    }

    [WindowsReferralFact]
    public async Task Native_basic_referrals_preserve_explicit_identity_across_primary_reuse_and_impersonation()
        => await CheckTlsReferral("127.0.0.1", "ldaps");

    [WindowsReferralDiagnosticTheory]
    [InlineData("localhost", "ldaps", false)]
    [InlineData("127.0.0.1", "ldaps", true)]
    [InlineData("127.0.0.1", "ldap", false)]
    [InlineData("localhost", "ldap", false)]
    public async Task Diagnostic_transport_and_name_variants(string host, string scheme, bool primaryCallback)
        => await CheckTlsReferral(host, scheme, primaryCallback);

    private async Task CheckTlsReferral(string host, string scheme, bool primaryCallback = false)
    {
        testHost = host;
        diagnosticPrimaryCallback = primaryCallback;
        output.WriteLine($"Primary LDAPS; referral scheme={scheme}; host={host}; primary callback={primaryCallback}; trusted diagnostic={Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") is not null}.");
        var target = new WindowsReferralEndpoint(tls: true);
        using var report = new FinalReport(() => output.WriteLine($"Final target: connections={target.Connections}; closed={target.Closed}; TLS={target.TlsHandshakes}; binds={target.Binds}; searches={target.Searches}; first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}."));
        await using var targetLifetime = target;
        await using var source = new WindowsReferralEndpoint(tls: true);
        // Load/JIT managed request and response dependencies before anonymous
        // impersonation, which cannot read assemblies from the runner workspace.
        // This separate primary never follows a referral.
        using (var warmup = Open(Options(source, WindowsReferralEndpoint.FirstIdentity)))
            Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(warmup));
        // The diagnostic also probes ldap:// URLs against a TLS-only target.
        // Never accept plaintext as a substitute for successful TLS here.
        source.ReferralUrl = $"{scheme}://{host}:{target.Port}/CN=target";
        using (var baseline = Open(Options(source, WindowsReferralEndpoint.FirstIdentity)))
        {
            try { Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(baseline)); }
            finally { output.WriteLine($"Baseline target connections={target.Connections}, TLS handshakes={target.TlsHandshakes}, binds={target.Binds}, searches={target.Searches}, SASL={target.SaslBinds}, certificate callbacks={certificateCallbacks}, first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}."); }
        }
        void Stage(string name, Action action)
        {
            try { action(); }
            finally { output.WriteLine($"Phase={name}; primary binds={source.Binds}; target connections={target.Connections}; TLS={target.TlsHandshakes}; binds={target.Binds}; searches={target.Searches}; anonymous={target.AnonymousBinds}; credentialed={target.CredentialedSimpleBinds}; SASL={target.SaslBinds}; first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}."); }
        }
        foreach (var identity in new[] { WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.SecondIdentity })
        {
            var options = Options(source, identity);
            using var connection = Open(options);
            // First referred bind happens only after changing ambient identity.
            Stage("first referral under anonymous impersonation", () => AsAnonymous(() => Assert.Equal(identity, Read(connection))));
            Stage("reuse under original identity", () => Assert.Equal(identity, Read(connection)));
            Stage("reuse under anonymous impersonation", () => AsAnonymous(() => Assert.Equal(identity, Read(connection))));
            // Fresh-primary baseline under the changed ambient identity.
            Stage("fresh control under anonymous impersonation", () => AsAnonymous(() =>
            {
                using var fresh = Open(options);
                Assert.Equal(identity, Read(fresh));
            }));
        }
        Assert.Equal(6, source.Binds); // Warmup, baseline, two retained, two fresh controls.
        Assert.Equal(10, source.Searches);
        Assert.Equal(9, target.Searches);
        Assert.Equal(0, target.SaslBinds);
        Assert.Contains(WindowsReferralEndpoint.FirstIdentity, target.BoundIdentities);
        Assert.Contains(WindowsReferralEndpoint.SecondIdentity, target.BoundIdentities);
        output.WriteLine($"Native TLS referrals: primary binds={source.Binds}, target searches={target.Searches}, target binds={target.Binds}, SASL binds={target.SaslBinds}. Two synthetic identities and six successful anonymous impersonation scopes; no referral callback overrides.");
    }

    [WindowsReferralFact]
    public async Task Native_plaintext_basic_referral_does_not_forward_credentials()
    {
        await using var target = new WindowsReferralEndpoint(tls: false);
        await using var source = new WindowsReferralEndpoint(tls: false)
        {
            ReferralUrl = $"ldap://127.0.0.1:{target.Port}/CN=target",
        };
        using var connection = Open(Options(source, WindowsReferralEndpoint.FirstIdentity, tls: false));
        var response = (SearchResponse)connection.SendRequest(new SearchRequest("CN=source", "(objectClass=*)",
            SearchScope.Base, "description"));
        Assert.Empty(response.Entries.Cast<SearchResultEntry>());
        Assert.NotEmpty(response.Referral);
        Assert.Empty(target.BoundIdentities);
        Assert.Equal(0, target.CredentialedSimpleBinds);
        Assert.Equal(0, target.SaslBinds);
        Assert.Equal(0, target.Searches);
        output.WriteLine($"Native plaintext Basic referral rejected; target anonymous binds={target.AnonymousBinds}, credentialed Simple binds={target.CredentialedSimpleBinds}, SASL binds={target.SaslBinds}.");
    }

    private sealed class FinalReport(Action write) : IDisposable
    {
        public void Dispose() => write();
    }

    private static void AsAnonymous(Action action)
    {
        if (!ImpersonateAnonymousToken(GetCurrentThread())) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { action(); }
        finally
        {
            if (!RevertToSelf()) Environment.FailFast("Could not restore the fixture thread's identity.");
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateAnonymousToken(IntPtr thread);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();
}
