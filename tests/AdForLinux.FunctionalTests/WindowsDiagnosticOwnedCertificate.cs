using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;

namespace AdForLinux.FunctionalTests;

// Test-only: opens an already-owned key; never creates/imports keys or modifies trust.
internal static class WindowsDiagnosticOwnedCertificate
{
    internal static X509Certificate2 Load(string directory, bool untrusted = false)
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
            throw new InvalidOperationException("Disposable hosted Windows required.");
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "provider-key.json")));
        var record = document.RootElement;
        string runId = record.GetProperty("RunId").GetString() ?? "";
        string name = record.GetProperty("Name").GetString() ?? "";
        const string provider = "Microsoft Software Key Storage Provider";
        using var identity = WindowsIdentity.GetCurrent();
        if (record.GetProperty("Version").GetInt32() != 1 || runId.Length != 32 ||
            runId.Any(c => !"0123456789abcdef".Contains(c)) || name != "adfl-auth-" + runId ||
            Path.GetFileName(directory) != name || record.GetProperty("State").GetString() != "owned" ||
            record.GetProperty("Sid").GetString() != identity.User?.Value ||
            record.GetProperty("Provider").GetString() != provider)
            throw new InvalidDataException("Invalid provider-key ownership.");
        using var key = CngKey.Open(name, new CngProvider(provider), CngKeyOpenOptions.None);
        if (key.IsMachineKey || key.IsEphemeral || key.KeyName != name || key.Provider?.Provider != provider ||
            key.ExportPolicy != CngExportPolicies.None || key.Algorithm != CngAlgorithm.Rsa || key.KeySize != 2048)
            throw new InvalidDataException("Unexpected provider key.");
        using var rsa = new RSACng(key);
        if (Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())) != record.GetProperty("PublicHash").GetString())
            throw new InvalidDataException("Provider-key public identity mismatch.");
        if (untrusted)
        {
            // Same owned non-exportable key, new public certificate ONLY. Never
            // imported into Root; distinct issuer/subject prevents root substitution.
            var request = new CertificateRequest("CN=ADFL untrusted " + runId, rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(System.Net.IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        }
#pragma warning disable SYSLIB0057
        using var certificate = new X509Certificate2(Path.Combine(directory, "loopback.cer"));
#pragma warning restore SYSLIB0057
        if (certificate.HasPrivateKey) throw new InvalidDataException("Public certificate required.");
        // CopyWithPrivateKey checks the certificate's public key matches. The named key
        // remains owned by the supervisor and is deleted only after workers terminate.
        return certificate.CopyWithPrivateKey(rsa);
    }
}
