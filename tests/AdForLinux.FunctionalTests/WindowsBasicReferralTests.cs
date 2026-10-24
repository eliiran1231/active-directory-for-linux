using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

public sealed class WindowsReferralDiagnosticFactAttribute : FactAttribute
{
    public WindowsReferralDiagnosticFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") is null)
            Skip = "Opt-in hosted certificate-trust diagnostic only.";
    }
}

public sealed partial class WindowsBasicReferralTests(ITestOutputHelper output)
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

    [WindowsReferralFact]
    public Task Direct_target_tls_normal_validation_under_original_identity()
        => CheckDirectTargetTls(anonymous: false, pinned: false);

    [WindowsReferralFact]
    public Task Direct_target_tls_normal_validation_under_anonymous_impersonation()
        => CheckDirectTargetTls(anonymous: true, pinned: false);

    [WindowsReferralFact]
    public void Native_chain_engine_probe_under_original_and_anonymous_identity()
    {
        // Independent of LDAP, system trust changes and the diagnostic PFX.
        // Generate only in memory; pass public DER to the native probe.
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN=ADFL chain probe {Guid.NewGuid():N}", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
#pragma warning disable SYSLIB0057
        using var publicCertificate = new X509Certificate2(generated.Export(X509ContentType.Cert));
#pragma warning restore SYSLIB0057
        // Warm the exact native/managed path before the existing anonymous scope.
        var original = WindowsChainProbe.Read(publicCertificate);
        WindowsChainProbe.Result anonymous = default;
        AsAnonymous(() => anonymous = WindowsChainProbe.Read(publicCertificate));
        // Log only after reverting identity. Native error and trust flags are
        // mutually exclusive: TRUE means a chain was built, not that it is trusted.
        foreach (var (identity, result) in new[] { ("original", original), ("anonymous", anonymous) })
        {
            var detail = result.ApiSucceeded
                ? $"trust-errors={result.TrustErrors:X8}; trust-info={result.TrustInfo:X8}"
                : $"native-error={result.NativeError:X8}";
            output.WriteLine($"Chain probe: identity={identity}; engine=current-user; flags={WindowsChainProbe.Flags:X8}; API-success={result.ApiSucceeded}; {detail}.");
        }
        Assert.True(original.ApiSucceeded, "Original identity must build a chain for the synthetic untrusted certificate.");
        foreach (var result in new[] { original, anonymous })
        {
            if (result.ApiSucceeded)
            {
                Assert.Null(result.NativeError);
                Assert.NotNull(result.TrustErrors);
                Assert.NotNull(result.TrustInfo);
                Assert.NotEqual(0u, result.TrustErrors!.Value & 0x20u); // CERT_TRUST_IS_UNTRUSTED_ROOT
            }
            else
            {
                Assert.NotNull(result.NativeError);
                Assert.NotEqual(0u, result.NativeError!.Value);
                Assert.Null(result.TrustErrors);
                Assert.Null(result.TrustInfo);
            }
        }
    }

    [WindowsReferralDiagnosticFact]
    public Task Diagnostic_normal_trust_original_identity()
        => CheckDirectTargetTls(anonymous: false, pinned: false, diagnosticCertificate: true);

    [WindowsReferralDiagnosticFact]
    public Task Diagnostic_normal_trust_anonymous_identity()
        => CheckDirectTargetTls(anonymous: true, pinned: false, diagnosticCertificate: true);

    [WindowsReferralDiagnosticFact]
    public Task Diagnostic_original_identity_referral_baseline()
        => CheckTlsReferral("127.0.0.1", "ldaps", stage: ReferralStage.OriginalBaseline);

    [WindowsReferralDiagnosticFact]
    public Task Diagnostic_original_identity_referral_reuse()
        => CheckTlsReferral("127.0.0.1", "ldaps", stage: ReferralStage.OriginalReuse);

    [WindowsReferralDiagnosticFact]
    public Task Diagnostic_impersonation_referral_safety()
        => CheckTlsReferral("127.0.0.1", "ldaps");

    private async Task CheckDirectTargetTls(bool anonymous, bool pinned = true, bool diagnosticCertificate = false)
    {
        // Independent direct controls, not referral or pool-safety assertions.
        // Warm the same client/callback path before impersonation: anonymous
        // threads cannot load assemblies from the runner workspace.
        int callbacks = 0;
        string phase = "initialization";
        string managedOutcome = "not requested";
        Action CreateRead(WindowsReferralEndpoint endpoint, bool usePin)
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
                if (diagnosticCertificate)
                    WindowsTlsDiagnosticControl.ObserveThenRun(() =>
                    {
#pragma warning disable SYSLIB0057
                        using var publicCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pin);
#pragma warning restore SYSLIB0057
                        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                        return chain.Build(publicCertificate) &&
                            publicCertificate.Thumbprint == chain.ChainElements[^1].Certificate.Thumbprint;
                    }, NativeRead, out managedOutcome);
                else NativeRead();
            };
            void NativeRead()
            {
                phase = "create";
                using var connection = LdapConnectionFactory.Create(options);
                // Exact DER pin on this client only; no trust-store changes and
                // no callback attached to native referral children.
                if (usePin) connection.SessionOptions.VerifyServerCertificate = (_, presented) =>
                {
                    Interlocked.Increment(ref callbacks);
                    return presented is not null && pin.AsSpan().SequenceEqual(presented.GetRawCertData());
                };
                phase = "bind";
                connection.Bind();
                phase = "search";
                Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(connection));
                phase = "complete";
            }
        }
        var warmup = new WindowsReferralEndpoint(tls: true, allowDiagnosticCertificate: diagnosticCertificate);
        using (var warmupReport = new FinalReport(() => output.WriteLine(
            $"Direct warmup: managed chain={managedOutcome}; phase={phase}; TLS={warmup.TlsHandshakes}; binds={warmup.Binds}; " +
            $"searches={warmup.Searches}; pin callbacks={callbacks}; failures={string.Join(";", warmup.TransportFailures)}.")))
        {
            await using var warmupLifetime = warmup;
            CreateRead(warmup, usePin: !diagnosticCertificate)();
        }
        callbacks = 0;
        managedOutcome = "not requested";
        var target = new WindowsReferralEndpoint(tls: true, allowDiagnosticCertificate: diagnosticCertificate);
        using var report = new FinalReport(() => output.WriteLine(
            $"Direct target: ambient={(anonymous ? "anonymous" : "original")}; validation={(pinned ? "exact pin" : "normal")}; diagnostic certificate={diagnosticCertificate}; managed chain={managedOutcome}; phase={phase}; " +
            $"connections={target.Connections}; closed={target.Closed}; TLS={target.TlsHandshakes}; " +
            $"binds={target.Binds}; searches={target.Searches}; credentialed={target.CredentialedSimpleBinds}; " +
            $"anonymous binds={target.AnonymousBinds}; SASL={target.SaslBinds}; pin callbacks={callbacks}; " +
            $"first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}."));
        Exception? failure;
        {
            await using var lifetime = target;
            var read = CreateRead(target, pinned);
            phase = "enter identity scope";
            failure = Record.Exception(() =>
            {
                if (anonymous) AsAnonymous(read);
                else read();
            });
            // Quiesce server tasks before checking negative counters: a failed
            // client request alone does not synchronize server processing.
        }
        if (failure is not null)
            output.WriteLine($"Direct client failure: {DescribeClientFailure(failure)}");
        if (!pinned && !diagnosticCertificate)
        {
            // A freshly generated self-signed certificate is not trusted. Normal
            // WinLDAP validation must fail before any synthetic credentials or
            // searches reach this target. Do not attach a validation callback.
            Assert.IsType<LdapException>(failure);
            Assert.Equal("bind", phase);
            Assert.Equal(1, target.Connections);
            Assert.Equal(1, target.Closed);
            Assert.Equal(0, target.TlsHandshakes);
            Assert.Equal(0, target.Binds);
            Assert.Equal(0, target.Searches);
            Assert.Equal(0, callbacks);
            return;
        }
        Assert.Null(failure);
        Assert.Equal(1, target.Connections);
        Assert.Equal(1, target.Closed);
        Assert.Equal(1, target.TlsHandshakes);
        Assert.Equal(1, target.Binds);
        Assert.Equal(1, target.CredentialedSimpleBinds);
        Assert.Equal(1, target.Searches);
        Assert.Equal(0, target.AnonymousBinds);
        Assert.Equal(0, target.SaslBinds);
        if (pinned) Assert.True(callbacks > 0, "The direct client must validate the exact test certificate.");
        else Assert.Equal(0, callbacks); // Normal native validation, never a pinning bypass.
    }

    private static string DescribeClientFailure(Exception error)
    {
        var details = new List<string>();
        for (Exception? current = error; current is not null; current = current.InnerException)
            details.Add($"{current.GetType().Name}:HResult={current.HResult:X8}" +
                (current is LdapException ldap ? $":LdapError={ldap.ErrorCode}" : "") +
                (current is Win32Exception native ? $":Native={native.NativeErrorCode}" : ""));
        return string.Join("/", details); // No exception messages, identities or payloads.
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

    private enum ReferralStage { Impersonation, OriginalBaseline, OriginalReuse }

    private async Task CheckTlsReferral(string host, string scheme, bool primaryCallback = false,
        ReferralStage stage = ReferralStage.Impersonation)
    {
        if (stage != ReferralStage.Impersonation)
        {
            Assert.NotNull(Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX"));
            Assert.False(primaryCallback);
        }
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
            var since = DateTime.UtcNow;
            try { Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(baseline)); }
            catch (Exception error)
            {
                output.WriteLine($"Referral operation/assertion failure: {DescribeClientFailure(error)}");
                throw;
            }
            finally
            {
                output.WriteLine($"Baseline target connections={target.Connections}, TLS handshakes={target.TlsHandshakes}, binds={target.Binds}, searches={target.Searches}, SASL={target.SaslBinds}, certificate callbacks={certificateCallbacks}, first records={string.Join(";", target.FirstRecords)}; failures={string.Join(";", target.TransportFailures)}.");
                MatchExistingSchannelCertificate(target, since);
            }
        }
        if (stage != ReferralStage.Impersonation)
        {
            Assert.Equal(0, certificateCallbacks);
            Assert.Equal(1, target.TlsHandshakes);
            Assert.Equal(1, target.Binds);
            Assert.Equal(1, target.CredentialedSimpleBinds);
            Assert.Equal(1, target.Searches);
            Assert.Equal(0, target.AnonymousBinds);
            Assert.Equal(0, target.SaslBinds);
            Assert.Contains(WindowsReferralEndpoint.FirstIdentity, target.BoundIdentities);
            output.WriteLine("Original-identity referral baseline passed: normal TLS, explicit Basic identity and search; no impersonation safety claim.");
            if (stage == ReferralStage.OriginalBaseline) return;
            foreach (var identity in new[] { WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.SecondIdentity })
            {
                using var retained = Open(Options(source, identity));
                Stage("original identity first referral", () => Assert.Equal(identity, Read(retained)));
                Stage("original identity primary reuse", () => Assert.Equal(identity, Read(retained)));
            }
            Assert.Equal(4, source.Binds);
            Assert.Equal(6, source.Searches);
            Assert.Equal(5, target.Searches);
            Assert.Equal(0, target.AnonymousBinds);
            Assert.Equal(0, target.SaslBinds);
            Assert.Equal(0, certificateCallbacks);
            Assert.Contains(WindowsReferralEndpoint.SecondIdentity, target.BoundIdentities);
            output.WriteLine("Original-identity primary reuse passed with two explicit identities; no ambient-identity, eviction or full pooling safety claim.");
            return;
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

    private void MatchExistingSchannelCertificate(WindowsReferralEndpoint target, DateTime since)
    {
        if (Environment.GetEnvironmentVariable("ADFL_REFERRAL_MATCH_EVENT") != "1") return;
        if (Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX") is not null)
            throw new InvalidOperationException("Attribution requires a hosted runner and a unique generated target certificate.");
        using var process = new System.Diagnostics.Process();
        process.StartInfo = new System.Diagnostics.ProcessStartInfo("pwsh")
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            Path.Combine(AppContext.BaseDirectory, "Match-SchannelCertificate.ps1") })
            process.StartInfo.ArgumentList.Add(argument);
        var started = false;
        try
        {
            started = process.Start();
            if (!started) throw new InvalidOperationException();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            process.StandardInput.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
            {
                Certificate = Convert.ToBase64String(target.PublicCertificateBytes), Since = since.ToString("O"),
            }));
            process.StandardInput.Close();
            if (!process.WaitForExit(20000))
            {
                process.Kill(entireProcessTree: true);
                if (!process.WaitForExit(10000)) throw new InvalidOperationException();
                output.WriteLine("Schannel attribution: context=reader timeout; exact-target-match=False");
                return;
            }
            if (!Task.WaitAll(new Task[] { stdout, stderr }, 5000)) throw new InvalidOperationException();
            // The reviewed script emits only attribution metadata. Do not print
            // stderr, which could contain source lines after a parser failure.
            if (process.ExitCode == 0)
            {
                foreach (var line in stdout.Result.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var safe = line.TrimEnd('\r');
                    if (System.Text.RegularExpressions.Regex.IsMatch(safe,
                        @"^Schannel attribution: (event=36882; utc=[0-9T:.Z+\-]+; context=(whole-DER payload|certificate payload unavailable or unsupported)|context=(no matching event in bounded observation window|read or parser unavailable)); exact-target-match=(True|False)$"))
                        output.WriteLine(safe);
                    else output.WriteLine("Schannel attribution: context=unexpected reader output withheld; exact-target-match=False");
                }
            }
            else output.WriteLine("Schannel attribution: context=reader failed; exact-target-match=False");
        }
        catch
        {
            output.WriteLine("Schannel attribution: context=reader unavailable; exact-target-match=False");
        }
        finally
        {
            if (started && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                if (!process.WaitForExit(10000)) throw new InvalidOperationException("Attribution reader did not stop.");
            }
        }
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
