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
public sealed class WindowsBasicReferralTests(ITestOutputHelper output)
{
    private int certificateCallbacks;
    private static LdapConnectionOptions Options(WindowsReferralEndpoint source, string identity, bool tls = true) => new()
    {
        Host = "127.0.0.1", Port = source.Port, UseSsl = tls,
        // Existing per-connection test option, scoped to this ephemeral loopback
        // certificate. No machine trust settings or production defaults change.
        SkipCertificateCheck = tls, BindDn = identity, BindPassword = WindowsReferralEndpoint.Password,
        Timeout = TimeSpan.FromSeconds(5),
    };

    private LdapConnection Open(LdapConnectionOptions options)
        => LdapConnectionFactory.ConfigureOwned(LdapConnectionFactory.Create(options), connection =>
        {
            LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.External);
            if (options.UseSsl)
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
    public async Task Native_basic_referrals_preserve_explicit_identity_across_primary_reuse_and_impersonation()
    {
        await using var target = new WindowsReferralEndpoint(tls: true);
        await using var source = new WindowsReferralEndpoint(tls: true);
        // Load/JIT managed request and response dependencies before anonymous
        // impersonation, which cannot read assemblies from the runner workspace.
        // This separate primary never follows a referral.
        using (var warmup = Open(Options(source, WindowsReferralEndpoint.FirstIdentity)))
            Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(warmup));
        // Explicit LDAPS URL: ldap:// to a custom port does not inherit TLS
        // in WinLDAP. Never accept plaintext as a substitute for this check.
        source.ReferralUrl = $"ldaps://127.0.0.1:{target.Port}/CN=target";
        using (var baseline = Open(Options(source, WindowsReferralEndpoint.FirstIdentity)))
        {
            try { Assert.Equal(WindowsReferralEndpoint.FirstIdentity, Read(baseline)); }
            finally { output.WriteLine($"Baseline target connections={target.Connections}, TLS handshakes={target.TlsHandshakes}, binds={target.Binds}, searches={target.Searches}, SASL={target.SaslBinds}, certificate callbacks={certificateCallbacks}."); }
        }
        foreach (var identity in new[] { WindowsReferralEndpoint.FirstIdentity, WindowsReferralEndpoint.SecondIdentity })
        {
            var options = Options(source, identity);
            using var connection = Open(options);
            // First referred bind happens only after changing ambient identity.
            AsAnonymous(() => Assert.Equal(identity, Read(connection)));
            Assert.Equal(identity, Read(connection));
            AsAnonymous(() => Assert.Equal(identity, Read(connection)));
            // Fresh-primary baseline under the changed ambient identity.
            AsAnonymous(() =>
            {
                using var fresh = Open(options);
                Assert.Equal(identity, Read(fresh));
            });
        }
        Assert.Equal(6, source.Binds); // Warmup, baseline, two retained, two fresh controls.
        Assert.Equal(10, source.Searches);
        Assert.Equal(9, target.Searches);
        Assert.Equal(0, target.SaslBinds);
        Assert.Contains(WindowsReferralEndpoint.FirstIdentity, target.BoundIdentities);
        Assert.Contains(WindowsReferralEndpoint.SecondIdentity, target.BoundIdentities);
        output.WriteLine($"Native TLS referrals: primary binds={source.Binds}, target searches={target.Searches}, target binds={target.Binds}, SASL binds={target.SaslBinds}. Two synthetic identities and six successful anonymous impersonation scopes; no callback overrides.");
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
