using System.Security.Cryptography;
using System.Text.Json;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.DifferentialTests;

// Expected values are Microsoft-only recordings, never the original clone output.
internal static class RecordedMicrosoftOracle
{
    private static readonly JsonDocument Recording = Load();

    public static string Read(string caseId)
    {
        var cases = Recording.RootElement.GetProperty("cases");
        Assert.True(cases.TryGetProperty(caseId, out var row), $"No recorded Microsoft observation for {caseId}");
        Assert.Equal("Passed", row.GetProperty("sourceOutcome").GetString());
        // Intentional differences require a separately reviewed policy. None in this pilot.
        Assert.Equal("match-microsoft", row.GetProperty("policy").GetString());
        return row.GetProperty("microsoft").GetString()!;
    }

    private static JsonDocument Load()
    {
        Assert.True(OfflineTestGuard.Enabled, "Use tests/differential-replay/run.py with the offline guard.");
        var framework = $"net{Environment.Version.Major}.0";
        Assert.Contains(framework, new[] { "net8.0", "net10.0" });
        var assembly = typeof(RecordedMicrosoftOracle).Assembly;
        using var manifestStream = assembly.GetManifestResourceStream("DifferentialOracle.manifest.json")!;
        using var manifest = JsonDocument.Parse(manifestStream);
        Assert.Equal(1, manifest.RootElement.GetProperty("schemaVersion").GetInt32());
        var entry = manifest.RootElement.GetProperty("fixtures").EnumerateArray()
            .Single(row => row.GetProperty("path").GetString() == $"run202-{framework}.json");
        using var stream = assembly.GetManifestResourceStream($"DifferentialOracle.{framework}.json")!;
        using var bytes = new MemoryStream();
        stream.CopyTo(bytes);
        var data = bytes.ToArray();
        Assert.Equal(entry.GetProperty("sha256").GetString(), Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        var recording = JsonDocument.Parse(data);
        Assert.Equal(1, recording.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(framework, recording.RootElement.GetProperty("framework").GetString());
        Assert.Equal(42, recording.RootElement.GetProperty("cases").EnumerateObject().Count());
        return recording;
    }
}
