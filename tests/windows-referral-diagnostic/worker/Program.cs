using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AdForLinux.FunctionalTests;

internal sealed record Envelope(int Version, string AHandle, string BHandle, string ASid, string BSid,
    string Root, string Thumbprint, bool TestOnly = false);
internal static class Program
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    public static int Main(string[] args)
    {
        if (args.SequenceEqual(new[] { "--context-query-report-self-test" }))
        {
            Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Report = new WindowsContextQueryProbe.Result(
                "restrictions-length", "length", 1, "restrictions-length", "length", 1, false, false,
                "eligible", "none", 0, "eligible", "none", 0, true, true) }));
            return 0;
        }
        if (args.SequenceEqual(new[] { "--context-query-probe" }))
        {
            var result = WindowsContextQueryProbe.Run();
            Console.Write(JsonSerializer.Serialize(result));
            return result.FixedEligible && result.FixedStable ? 0 : 1;
        }
        // Explicit pure entry point: no Windows calls, fixture creation or secrets.
        if (args.SequenceEqual(new[] { "--pool-report-self-test" })) { PoolReportSelfTest(); return 0; }
        if (args.SequenceEqual(new[] { "--context-report-self-test" }))
        {
            var native = WindowsAuthenticatedDiagnostic.Schedule((_, stage) =>
                new("passed", stage == "retained-primary" || stage == "transition" ? 4 : 2,
                    stage == "retained-primary" || stage == "transition" ? 4 : 2,
                    stage == "retained-primary" || stage == "transition" ? 4 : 2,
                    stage == "retained-primary" || stage == "transition" ? 4 : 2, 0, 0,
                    stage == "direct" ? 0 : 2, stage == "direct" ? 0 : stage == "referral" ? 2 : 4,
                    stage == "retained-primary" || stage == "transition" ? 4 : 2));
            native["anonymous-direct"] = new("failed", 1, 0, 0, 0, 0, 0);
            var candidate = WindowsContextCandidateDiagnostic.Schedule(native, name =>
            {
                var parts = name.Split('/'); string owner = parts[0], scenario = parts[1];
                var row = new WindowsContextCandidateDiagnostic.Observation("passed", 1, 1, 1, 1, 1, 1, 0, false, true, 0);
                return scenario switch
                {
                    "stable" => row with { Attempts = 3, TargetSearches = 3 },
                    "failed-bind" => row with { Attempts = 2, ObservedCode = 49, ObservedKind = "ldap" },
                    "primary-failure" or "target-failure" => row with { Attempts = 3, SourceBinds = 2, ObservedCode = 81, ObservedKind = "ldap" },
                    "findone" => row with { Attempts = 2, SourceBinds = 4, SourceSearches = 7, TargetSearches = 2 },
                    _ when owner == "partition" => row with { Attempts = 3, SourceBinds = 2, TargetSearches = 3 },
                    _ when owner == "anonymous" && scenario is not ("complete" or "return") => row with { Attempts = scenario is "acquired" or "send" ? 2 : 3, FreshCode = 81, WarmCode = 81, FreshKind = "ldap", WarmKind = "ldap" },
                    _ => row
                };
            });
            Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Report = WindowsContextCandidateDiagnostic.CreateReport(native, candidate) }));
            return 0;
        }
        if (args.SequenceEqual(new[] { "--continuation-report-self-test" }) || args.SequenceEqual(new[] { "--external-scope-report-self-test" }))
        {
            var native = WindowsAuthenticatedDiagnostic.Schedule((_, stage) =>
                new("passed", stage is "retained-primary" or "transition" ? 4 : 2,
                    stage is "retained-primary" or "transition" ? 4 : 2,
                    stage is "retained-primary" or "transition" ? 4 : 2,
                    stage is "retained-primary" or "transition" ? 4 : 2, 0, 0,
                    stage == "direct" ? 0 : 2, stage == "direct" ? 0 : stage == "referral" ? 2 : 4,
                    stage is "retained-primary" or "transition" ? 4 : 2));
            native["anonymous-direct"] = new("failed", 1, 0, 0, 0, 0, 0);
            bool external = args[0] == "--external-scope-report-self-test";
            WindowsContinuationDiagnostic.Comparison MakeCase(string name)
            {
                bool partial = !external && name.EndsWith("/partial", StringComparison.Ordinal);
                var ordinary = new WindowsContinuationDiagnostic.Observation("passed", "complete", "none", 0,
                    true, 0, 2, 2, [partial ? 4 : 0, partial ? 4 : 0], [external ? "target" : "local", external ? "target" : "local"],
                    3, 7, 1, 4, external ? 0 : 2, external ? 0 : 2, 2, 2, true, 0);
                var scoped = ordinary with { SourceBinds = partial ? 5 : 4, Reused = partial ? 0 : 1 };
                return new("passed", true, ordinary, scoped);
            }
            if (external)
            {
                var externalCases = WindowsContinuationDiagnostic.ScheduleExternal(native, MakeCase);
                var report = new WindowsContinuationDiagnostic.ExternalReport(native, externalCases, "passed", "failed", false);
                Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Report = report }));
                return 0;
            }
            var cases = WindowsContinuationDiagnostic.Schedule(native, MakeCase);
            Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Report = WindowsContinuationDiagnostic.CreateReport(native, cases) }));
            return 0;
        }
        if (args.SequenceEqual(new[] { "--self-test" })) { SelfTest(); return 0; }
        if (args.SequenceEqual(new[] { "--certificate-material-self-test" })) return CertificateMaterialSelfTest();
        if (args.Length == 2 && args[0] == "--setup-e2e") return SetupEndToEnd(args[1]);
        if (args.Length == 2 && args[0] == "--e2e-wait" && E2EHost())
        {
            ValidateE2ERoot(args[1]);
            string ready = Path.Combine(args[1], "e2e-descendant-started.txt");
            File.WriteAllText(ready + ".new", Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
            File.Move(ready + ".new", ready);
            Thread.Sleep(Timeout.Infinite); return 2;
        }
        bool contextCandidate = args.SequenceEqual(new[] { "--context-candidate" });
        bool continuationCandidate = args.SequenceEqual(new[] { "--continuation-candidate" });
        bool externalScopeCandidate = args.SequenceEqual(new[] { "--external-scope-candidate" });
        if ((!contextCandidate && !continuationCandidate && !externalScopeCandidate && args.Length != 0) || !OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted") return 2;
        try
        {
            // Child stays behind this bounded pipe barrier until handles are copied.
            var request = JsonSerializer.Deserialize<Envelope>(AdflPrivateFrame.Read(Console.OpenStandardInput()), Json)
                ?? throw new InvalidDataException();
            Validate(request, Environment.GetEnvironmentVariable("LOCALAPPDATA"));
            ValidateExecutionMode(request.TestOnly, false);
            AdflProcessJob.VerifyCurrentMembership("Local\\" + Path.GetFileName(request.Root));
            using var a = AdflAuthenticatedToken.Adopt(long.Parse(request.AHandle, CultureInfo.InvariantCulture), request.ASid);
            using var b = AdflAuthenticatedToken.Adopt(long.Parse(request.BHandle, CultureInfo.InvariantCulture), request.BSid);
            string publicCertificate = Path.Combine(request.Root, "loopback.cer");
#pragma warning disable SYSLIB0057
            using (var certificate = new X509Certificate2(publicCertificate))
#pragma warning restore SYSLIB0057
                if (certificate.HasPrivateKey || certificate.Thumbprint != request.Thumbprint) throw new InvalidDataException();
            Environment.SetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX", null);
            Environment.SetEnvironmentVariable("ADFL_REFERRAL_OWNED_KEY_DIRECTORY", request.Root);
            var native = WindowsAuthenticatedDiagnostic.Run(a.Run, b.Run);
            if (externalScopeCandidate)
            {
                var comparison = WindowsContinuationDiagnostic.RunExternal(native);
                Console.Out.Write(JsonSerializer.Serialize(comparison));
                return comparison.AllPassed ? 0 : 1;
            }
            if (continuationCandidate)
            {
                var comparison = WindowsContinuationDiagnostic.Run(native);
                Console.Out.Write(JsonSerializer.Serialize(comparison));
                return comparison.AllPassed ? 0 : 1;
            }
            if (contextCandidate)
            {
                var candidate = WindowsContextCandidateDiagnostic.Run(native, a.Run, b.Run);
                var candidateResult = WindowsContextCandidateDiagnostic.CreateReport(native, candidate);
                Console.Out.Write(JsonSerializer.Serialize(candidateResult));
                return candidateResult.AllPassed ? 0 : 1;
            }
            var pool = WindowsReferralPoolDiagnostic.Run(native, a.Run, b.Run);
            var result = WindowsDiagnosticReport.Create(native, pool);
            // Result keys/status/counters only. Never include input, handles or exceptions.
            Console.Out.Write(JsonSerializer.Serialize(result));
            return result.AllPassed ? 0 : 1;
        }
        catch { return 2; } // No raw errors or stack traces on either output stream.
    }
    private static void PoolReportSelfTest()
    {
        // Serialization/PowerShell-consumption contract only; no endpoint or OS calls.
        var native = WindowsAuthenticatedDiagnostic.Schedule((identity, stage) =>
        {
            if (identity == "anonymous") return new("failed", 1, 0, 0, 0, 0, 0, Closed: 1, Phase: "bind", FailureKind: "ldap", FailureCode: 81);
            bool repeated = stage is "retained-primary" or "transition";
            int count = repeated ? 4 : 2;
            return new("passed", count, count, count, count, 0, 0,
                stage == "direct" ? 0 : 2, stage == "direct" ? 0 : count, count);
        });
        var pool = WindowsReferralPoolDiagnostic.Schedule(native, (_, scenario) =>
        {
            bool untrusted = scenario == "untrusted-target", rejected = scenario == "target-bind-rejection";
            bool disconnected = scenario.EndsWith("disconnect");
            var timeline = new List<string>();
            if (scenario.EndsWith("concurrent"))
            {
                var records = new List<(string Role, int Operation, string Stage)>();
                foreach (int operation in new[] { 1, 2 }) records.Add(("client", operation, "native-enter"));
                foreach (int operation in new[] { 1, 2 })
                { records.Add(("source", operation, "search")); records.Add(("source", operation, "arrive")); }
                foreach (int operation in new[] { 1, 2 })
                    foreach (var pair in new[] { ("source", "release"), ("source", "referral-send"),
                        ("target", "search"), ("target", "response-send"), ("client", "native-exit") })
                        records.Add((pair.Item1, operation, pair.Item2));
                foreach (var record in records)
                {
                    int connection = record.Role == "source" ? int.MaxValue - 2 + record.Operation : int.MaxValue;
                    timeline.Add($"{timeline.Count + 1}:999999999999:{record.Role}:{connection}:2147483647:{record.Operation}:{record.Stage}");
                }
                // Maximum-width whole-report capacity, including all six 64-event traces.
                for (int padding = records.Count; padding < 64; padding++)
                    timeline.Add($"{timeline.Count + 1}:999999999999:target:2147483647:2147483647:0:response-send");
            }
            return new("passed", Checks: 3, PrimaryBinds: 2, TargetConnections: 2, TargetTls: untrusted ? 0 : 2,
                TargetBinds: untrusted ? 0 : 2, TargetSearches: untrusted || rejected ? 0 : 2,
                Closed: 2, ManagedAttempts: disconnected ? 3 : scenario.EndsWith("concurrent") ? 2 : 1, Cleanup: true,
                ObservedFailureKind: untrusted || rejected || disconnected ? "ldap" : "none",
                ObservedFailureCode: untrusted || rejected || disconnected ? 81 : 0,
                WorkersReady: scenario.EndsWith("concurrent") ? 2 : 0, OperationStarts: scenario.EndsWith("concurrent") ? 2 : 0,
                SourceOverlapArrivals: scenario.EndsWith("concurrent") ? 2 : 0, Timeline: string.Join(';', timeline));
        });
        Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Report = WindowsDiagnosticReport.Create(native, pool) }));
    }
    private static int CertificateMaterialSelfTest()
    {
        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromBase64String(AdflPrivateFrame.Read(Console.OpenStandardInput()));
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(bytes, "", X509KeyStorageFlags.EphemeralKeySet);
#pragma warning restore SYSLIB0057
            using var key = certificate.GetRSAPrivateKey() ?? throw new InvalidDataException();
            using var publicKey = certificate.GetRSAPublicKey() ?? throw new InvalidDataException();
            byte[] payload = System.Text.Encoding.UTF8.GetBytes("ADFL synthetic material verification");
            byte[] signature = key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            bool verified = publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.Write(JsonSerializer.Serialize(new { certificate.HasPrivateKey, SignatureVerified = verified, certificate.Thumbprint }));
            return verified ? 0 : 2;
        }
        catch { return 2; }
        finally { if (bytes is not null) Array.Clear(bytes); }
    }
    private static bool E2EHost() => OperatingSystem.IsWindows() && Environment.Is64BitProcess &&
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
        Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted";
    private static void ValidateE2ERoot(string root)
    {
        Validate(new Envelope(1, "101", "102", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", root, new string('A', 40), true),
            Environment.GetEnvironmentVariable("LOCALAPPDATA"));
        using var owner = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "owner.json")));
        if (!owner.RootElement.GetProperty("TestOnly").GetBoolean()) throw new InvalidDataException();
        AdflProcessJob.VerifyCurrentMembership("Local\\" + Path.GetFileName(root));
    }
    private static int SetupEndToEnd(string expectedRoot)
    {
        if (!E2EHost()) return 2;
        try
        {
            ValidateE2ERoot(expectedRoot);
#if NET8_0
            const string framework = "net8.0";
#else
            const string framework = "net10.0";
#endif
            File.WriteAllText(Path.Combine(expectedRoot, $"e2e-worker-ready-{framework}.txt"), "ready for frame");
            var request = JsonSerializer.Deserialize<Envelope>(AdflPrivateFrame.Read(Console.OpenStandardInput()), Json)
                ?? throw new InvalidDataException();
            Validate(request, Environment.GetEnvironmentVariable("LOCALAPPDATA"));
            ValidateExecutionMode(request.TestOnly, true);
            if (!string.Equals(request.Root, expectedRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            AdflE2ETransfer.VerifyAndClose(long.Parse(request.AHandle, CultureInfo.InvariantCulture), long.Parse(request.BHandle, CultureInfo.InvariantCulture));
            File.WriteAllText(Path.Combine(expectedRoot, $"e2e-handles-closed-{framework}.txt"), "two events verified and closed");
            using var owner = JsonDocument.Parse(File.ReadAllText(Path.Combine(request.Root, "owner.json")));
            if (!owner.RootElement.GetProperty("TestOnly").GetBoolean()) throw new InvalidDataException();
            AdflProcessJob.VerifyCurrentMembership("Local\\" + Path.GetFileName(request.Root));
            string scenario = File.ReadAllText(Path.Combine(request.Root, "e2e-case.txt"));
            if (scenario == "EarlyExit") { File.WriteAllText(Path.Combine(request.Root, "e2e-fault.txt"), scenario); return 3; }
            if (scenario == "RuntimeTimeout")
            {
                var info = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
                info.ArgumentList.Add(typeof(Program).Assembly.Location);
                info.ArgumentList.Add("--e2e-wait");
                info.ArgumentList.Add(request.Root);
                using var descendant = System.Diagnostics.Process.Start(info) ?? throw new InvalidOperationException();
                var timer = System.Diagnostics.Stopwatch.StartNew();
                string ready = Path.Combine(request.Root, "e2e-descendant-started.txt");
                while (!File.Exists(ready))
                {
                    if (descendant.HasExited || timer.ElapsedMilliseconds > 10000) throw new InvalidOperationException();
                    Thread.Sleep(25);
                }
                if (int.Parse(File.ReadAllText(ready), CultureInfo.InvariantCulture) != descendant.Id || descendant.HasExited)
                    throw new InvalidOperationException();
                File.WriteAllText(Path.Combine(request.Root, "e2e-fault.txt"), scenario);
                Thread.Sleep(Timeout.Infinite);
            }
            if (scenario == "MalformedOutput") { File.WriteAllText(Path.Combine(request.Root, "e2e-fault.txt"), scenario); Console.Write("{malformed"); return 0; }
            if (scenario == "OutputOverflow") { File.WriteAllText(Path.Combine(request.Root, "e2e-fault.txt"), scenario); Console.Write(new string('x', 70000)); return 0; }
            if (File.ReadAllText(Path.Combine(request.Root, "loopback.pfx")) != "DUMMY NON-SECRET PAYLOAD; NOT A CERTIFICATE OR KEY")
                throw new InvalidDataException();
            // Explicitly synthetic observations: no token adoption, impersonation, TLS or LDAP.
            var observations = WindowsAuthenticatedDiagnostic.Schedule((identity, stage) =>
            {
                bool direct = stage == "direct";
                int searches = stage is "retained-primary" or "transition" ? 4 : 2;
                return new("passed", 2, 2, 2, searches, 0, 0, direct ? 0 : 2, direct ? 0 : searches, 2);
            });
            Console.Write(JsonSerializer.Serialize(new { TestOnly = true, Observations = observations }));
            return 0;
        }
        catch { return 2; }
    }
    internal static void Validate(Envelope value, string? appData)
    {
        if (!Path.IsPathFullyQualified(value.Root)) throw new InvalidDataException();
        string root = Path.GetFullPath(value.Root);
        if (value.Version != 1 || string.IsNullOrEmpty(appData) || !Path.IsPathFullyQualified(appData) ||
            !Regex.IsMatch(Path.GetFileName(root), "^adfl-auth-[0-9a-f]{32}$") ||
            !string.Equals(Path.GetDirectoryName(root), Path.GetFullPath(Path.Combine(appData, "Temp")), StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(value.Thumbprint, "^[0-9A-F]{40}$") || value.ASid == value.BSid || value.AHandle == value.BHandle)
            throw new InvalidDataException();
        foreach (var sid in new[] { value.ASid, value.BSid })
            if (!Regex.IsMatch(sid, @"^S-1-5-21-\d+-\d+-\d+-\d+$")) throw new InvalidDataException();
        foreach (var handle in new[] { value.AHandle, value.BHandle })
            if (!Regex.IsMatch(handle, "^[1-9][0-9]{0,18}$") || !long.TryParse(handle, out long number) || number <= 0)
                throw new InvalidDataException();
    }
    internal static void ValidateExecutionMode(bool supplied, bool expected)
    {
        if (supplied != expected) throw new InvalidDataException();
    }
    private static void SelfTest()
    {
        ValidateExecutionMode(false, false); ValidateExecutionMode(true, true);
        foreach (bool supplied in new[] { false, true })
        {
            bool invalid = false;
            try { ValidateExecutionMode(supplied, !supplied); } catch (InvalidDataException) { invalid = true; }
            if (!invalid) throw new Exception("Cross-mode input accepted.");
        }
        string appData = Path.Combine(Path.GetTempPath(), "synthetic-appdata");
        string leaf = "adfl-auth-" + new string('a', 32);
        var envelope = new Envelope(1, "123", "456", "S-1-5-21-1-2-3-4", "S-1-5-21-1-2-3-5",
            Path.Combine(appData, "Temp", leaf), new string('A', 40));
        Validate(envelope, appData);
        foreach (string root in new[] { Path.Combine(appData, leaf), Path.Combine(appData, "Temp", "child", leaf), "relative" })
        {
            bool invalid = false;
            try { Validate(envelope with { Root = root }, appData); } catch (InvalidDataException) { invalid = true; }
            if (!invalid) throw new Exception("Unapproved diagnostic parent accepted.");
        }
        foreach (string? invalidAppData in new string?[] { null, "", "relative" })
        {
            bool invalid = false;
            try { Validate(envelope, invalidAppData); } catch (InvalidDataException) { invalid = true; }
            if (!invalid) throw new Exception("Invalid application-data root accepted.");
        }
        foreach (var failure in new[] { "a-direct", "b-direct", "original-direct", "a-referral", "a-retained-primary" })
        {
            var result = WindowsAuthenticatedDiagnostic.Schedule((identity, stage) =>
                new(identity + "-" + stage == failure ? "failed" : "passed", 0, 0, 0, 0, 0, 0));
            if (failure.StartsWith("a-") && (result["b-retained-primary"].Status != "passed" || result["a-to-b"].Status != "skipped"))
                throw new Exception("Stage dependency failed.");
            if (failure == "original-direct" && result["a-to-b"].Status != "passed") throw new Exception("Independent stages blocked.");
        }
        var rawPassing = WindowsAuthenticatedDiagnostic.Schedule((_, _) => new("passed", 0, 0, 0, 0, 0, 0));
        rawPassing["anonymous-direct"] = new("failed", 0, 0, 0, 0, 0, 0);
        var poolPassing = WindowsReferralPoolDiagnostic.Schedule(rawPassing, (_, _) => new("passed"));
        var combined = WindowsDiagnosticReport.Create(rawPassing, poolPassing);
        if (poolPassing.Count != 37 || combined.Supported != "passed" || combined.Adverse != "failed" || combined.AllPassed)
            throw new Exception("Separate supported/adverse verdict failed.");
        rawPassing["a-direct"] = new("failed", 0, 0, 0, 0, 0, 0);
        var gated = WindowsReferralPoolDiagnostic.Schedule(rawPassing, (_, _) => new("passed"));
        if (gated["a-isolation"].Status != "skipped" || gated["first-a-to-b"].Status != "skipped" || gated["b-concurrent"].Status != "passed")
            throw new Exception("Pool native dependency failed.");
        using var memory = new MemoryStream();
        AdflPrivateFrame.Write(memory, "synthetic-private-payload"); memory.Position = 0;
        if (AdflPrivateFrame.Read(memory) != "synthetic-private-payload") throw new Exception("Frame mismatch.");
        using var oversized = new MemoryStream(BitConverter.GetBytes(AdflPrivateFrame.Maximum + 1));
        bool rejected = false;
        try { AdflPrivateFrame.Read(oversized); } catch (InvalidDataException) { rejected = true; }
        if (!rejected) throw new Exception("Oversized input accepted.");
        if (Environment.Is64BitProcess && (AdflProcessJob.ExtendedSize != 144 || AdflProcessJob.AccountingSize != 48))
            throw new Exception("Native structure size mismatch.");
        Console.WriteLine("Pure worker stage, bounded-frame and interop-layout checks passed. No native operations executed.");
    }
}
