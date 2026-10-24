using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AdForLinux.FunctionalTests;

internal sealed record Envelope(int Version, string AHandle, string BHandle, string ASid, string BSid,
    string Root, string Thumbprint);
internal static class Program
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    public static int Main(string[] args)
    {
        // Explicit pure entry point: no Windows calls, fixture creation or secrets.
        if (args.SequenceEqual(new[] { "--self-test" })) { SelfTest(); return 0; }
        if (args.Length != 0 || !OperatingSystem.IsWindows() || !Environment.Is64BitProcess ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted") return 2;
        try
        {
            // Child stays behind this bounded pipe barrier until handles are copied.
            var request = JsonSerializer.Deserialize<Envelope>(AdflPrivateFrame.Read(Console.OpenStandardInput()), Json)
                ?? throw new InvalidDataException();
            Validate(request, Environment.GetEnvironmentVariable("LOCALAPPDATA"));
            AdflProcessJob.VerifyCurrentMembership("Local\\" + Path.GetFileName(request.Root));
            using var a = AdflAuthenticatedToken.Adopt(long.Parse(request.AHandle, CultureInfo.InvariantCulture), request.ASid);
            using var b = AdflAuthenticatedToken.Adopt(long.Parse(request.BHandle, CultureInfo.InvariantCulture), request.BSid);
            string pfx = Path.Combine(request.Root, "loopback.pfx");
#pragma warning disable SYSLIB0057
            using (var certificate = new X509Certificate2(pfx))
#pragma warning restore SYSLIB0057
                if (certificate.Thumbprint != request.Thumbprint) throw new InvalidDataException();
            Environment.SetEnvironmentVariable("ADFL_REFERRAL_TEST_PFX", pfx);
            var result = WindowsAuthenticatedDiagnostic.Run(a.Run, b.Run);
            // Result keys/status/counters only. Never include input, handles or exceptions.
            Console.Out.Write(JsonSerializer.Serialize(result));
            return result.Values.All(x => x.Status == "passed") ? 0 : 1;
        }
        catch { return 2; } // No raw errors or stack traces on either output stream.
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
    private static void SelfTest()
    {
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
