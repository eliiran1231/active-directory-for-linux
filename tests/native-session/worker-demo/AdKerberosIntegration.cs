using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.IntegrationTests;

internal static class AdKerberosIntegration
{
    private static readonly string[] Excluded = ["native-fault-injection", "in-flight-publication-race",
        "expiry-and-renewal", "wire-bind-counting", "windows-kerberos", "ambient-reuse"];
    private static void Report(string status, string stage, string commit, object? counters = null, string? errorCategory = null)
        => Console.WriteLine(JsonSerializer.Serialize(new { status, stage, commit,
            backend = "restricted-linux-owned-kerberos", authentication = "GSSAPI/sign+seal/no-TLS/no-referrals",
            runtime = Environment.Version.ToString(), counters, errorCategory, excluded = Excluded }));

    internal static async Task<int> Run(string configPath, string commit, bool execute)
    {
        var stage = "source-revision";
        var admitted = false;
        var outcome = 2;
        try
        {
            if (!Regex.IsMatch(commit, "^[0-9a-fA-F]{40}$")) throw new ArgumentException();
            var built = typeof(AdKerberosIntegration).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (built is null || !built.EndsWith("+" + commit, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException();
            if (!OperatingSystem.IsLinux()) { stage = "linux-runner-required"; throw new PlatformNotSupportedException(); }
            stage = "configuration";
            if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath) || new FileInfo(configPath).Length > 65536)
                throw new ArgumentException();
            var configuration = JsonSerializer.Deserialize<AdKerberosConfiguration>(File.ReadAllText(configPath),
                new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }) ?? throw new ArgumentException();
            configuration.Validate();
            stage = "admitted-deployment";
            using (var deployment = LdapWorkerDeployment.Validate(configuration.DeploymentDirectory))
                deployment.RequireRestrictedComposition();
            stage = "explicit-test-snapshot-files";
            foreach (var path in new[] { configuration.CacheA, configuration.CacheB })
                if (!File.Exists(path) || new FileInfo(path).Length is < 1 or > 1048576)
                    throw new ArgumentException();
            // Preflight stops before opening either credential file or binding.
            if (!execute) { Report("READY_NOT_AUTHENTICATED", "preflight", commit); return 0; }
            stage = "live-access-guard";
            OfflineTestGuard.RequireLiveAccess();
            admitted = true;
            if (LdapRestrictedOperation.Snapshot.Tracked != 0) throw new InvalidOperationException();
            stage = "owned-snapshot-import";
            using var owner = ReadOwner(configuration.CacheA);
            var profile = configuration.Profile(owner);
            using var root = profile.CreateDirectoryEntry(configuration.SearchBaseDn);
            stage = "first-public-paged-search";
            Read(configuration, root, false);
            var first = LdapRestrictedOperation.GroupCounters;
            if (first.Created == 0) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit, new { created = first.Created });
            stage = "separate-operation-reuse";
            Read(configuration, root, false);
            var repeated = LdapRestrictedOperation.GroupCounters;
            if (repeated.Created != first.Created || repeated.Reused <= first.Reused) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit, new { createdDelta = repeated.Created - first.Created, reuseDelta = repeated.Reused - first.Reused });

            stage = "separate-manager-identity-isolation";
            using (var other = ReadOwner(configuration.CacheB))
            using (var otherRoot = configuration.Profile(other).CreateDirectoryEntry(configuration.SearchBaseDn))
                Read(configuration, otherRoot, true);
            if (LdapRestrictedOperation.GroupCounters.Created <= repeated.Created) throw new InvalidOperationException();
            Read(configuration, root, false); // A remains A after the independent B operation.
            Report("CASE_PASSED", stage, commit);

            stage = "publication-switch";
            var beforePublication = LdapRestrictedOperation.GroupCounters;
            var replacement = ReadSnapshot(configuration.CacheB);
            try { owner.Publish(replacement); } finally { CryptographicOperations.ZeroMemory(replacement); }
            Read(configuration, root, true);
            var published = LdapRestrictedOperation.GroupCounters;
            if (published.Created <= beforePublication.Created) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit, new { createdDelta = published.Created - beforePublication.Created });

            stage = "close-forces-fresh";
            root.Close(); Read(configuration, root, true);
            if (LdapRestrictedOperation.GroupCounters.Created <= published.Created) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit, new { createdDelta = LdapRestrictedOperation.GroupCounters.Created - published.Created });
            stage = "precancelled-admission";
            var beforeCancel = LdapRestrictedOperation.GroupCounters;
            try
            {
                var sessions = LdapRestrictedOperation.Acquire(root.BuildOptions(), 1, ReferralChasingOption.None, new CancellationToken(true));
                foreach (var session in sessions) session.Dispose();
                throw new InvalidOperationException();
            }
            catch (OperationCanceledException) { }
            if (LdapRestrictedOperation.GroupCounters != beforeCancel) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit);
            stage = "disposed-manager-rejects-admission";
            owner.Dispose();
            try { Read(configuration, root, true); throw new InvalidOperationException(); }
            catch (ObjectDisposedException) { }
            if (LdapRestrictedOperation.GroupCounters != beforeCancel) throw new InvalidOperationException();
            Report("CASE_PASSED", stage, commit);
            outcome = 0;
        }
        catch (Exception error)
        {
            var category = error switch
            {
                UnauthorizedAccessException => "permission",
                FileNotFoundException or DirectoryNotFoundException => "missing-file",
                PlatformNotSupportedException => "unsupported-platform-or-profile",
                JsonException or ArgumentException => "invalid-configuration",
                InvalidDataException => "invalid-data",
                TimeoutException => "timeout", OperationCanceledException => "cancelled",
                DirectoryServicesCOMException => "directory-result", IOException => "io",
                InvalidOperationException => "policy-or-state", _ => "unexpected"
            };
            Report(admitted ? "FAILED" : "MISSING_PREREQUISITES", stage,
                Regex.IsMatch(commit, "^[0-9a-fA-F]{40}$") ? commit : "invalid", errorCategory: category);
            outcome = admitted ? 1 : 2;
        }
        finally
        {
            if (admitted)
            {
                var elapsed = Stopwatch.StartNew();
                while (LdapRestrictedOperation.Snapshot.Tracked != 0 && elapsed.Elapsed < TimeSpan.FromSeconds(15)) await Task.Delay(25);
                if (LdapRestrictedOperation.Snapshot.Tracked != 0) { Report("FAILED", "verified-worker-cleanup", commit); outcome = 1; }
            }
        }
        if (outcome == 0) Report("PASSED", "read-only-ad-interop", commit);
        return outcome;
    }

    private static byte[] ReadSnapshot(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 1048576) throw new InvalidDataException();
        var bytes = new byte[checked((int)file.Length)];
        try { file.ReadExactly(bytes); if (file.ReadByte() != -1) throw new InvalidDataException(); return bytes; }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }
    private static KerberosCredentialContext ReadOwner(string path)
    {
        var bytes = ReadSnapshot(path);
        try { return new KerberosCredentialContext(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void Read(AdKerberosConfiguration configuration, DirectoryEntry root, bool second)
    {
        using var search = new DirectorySearcher(root, configuration.SearchFilter,
            ["distinguishedName", configuration.MarkerAttribute], SearchScope.Subtree)
        { ReferralChasing = ReferralChasingOption.None, PageSize = 1, CacheResults = true,
            ClientTimeout = TimeSpan.FromSeconds(30) };
        using var results = search.FindAll();
        var rows = results.Cast<SearchResult>().ToArray();
        var expected = second ? configuration.ExpectedDnsB : configuration.ExpectedDnsA;
        var marker = second ? configuration.MarkerValueB : configuration.MarkerValueA;
        if (rows.Length != 2 || rows.Any(row => row.Properties["distinguishedName"].Count != 1 ||
                row.Properties[configuration.MarkerAttribute].Count != 1 ||
                (string?)row.Properties[configuration.MarkerAttribute][0] != marker) ||
            !rows.Select(row => (string)row.Properties["distinguishedName"][0]).Order(StringComparer.OrdinalIgnoreCase)
                .SequenceEqual(expected.Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException();
    }
}
