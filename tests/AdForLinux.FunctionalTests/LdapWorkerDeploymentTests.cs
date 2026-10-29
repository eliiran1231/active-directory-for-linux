using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class LdapWorkerDeploymentTests
{
    [Fact]
    public void Caller_policy_accepts_only_consistent_unprivileged_execution()
    {
        LdapWorkerDeployment.RequireCallerPolicy(1000, 1000, 1000, 1000, 1000, 1000, 0, 0, 0);
        // Secure mode remains disallowed even when all current IDs match.
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerDeployment.RequireCallerPolicy(1000, 1000, 1000, 1000, 1000, 1000, 1, 0, 0));
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerDeployment.RequireCallerPolicy(1000, 1000, 1000, 1000, 1000, 1000, 0, 1UL << 63, 0));
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerDeployment.RequireCallerPolicy(1000, 1000, 1000, 1000, 1000, 1000, 0, 0, 1UL << 63));
    }
    [Theory]
    [InlineData(0, 0, 0, 1000, 1000, 1000)]
    [InlineData(1000, 1001, 1000, 1000, 1000, 1000)]
    [InlineData(1000, 1000, 1001, 1000, 1000, 1000)]
    [InlineData(1001, 1000, 1000, 1000, 1000, 1000)]
    [InlineData(1000, 1000, 1000, 1000, 1001, 1000)]
    [InlineData(1000, 1000, 1000, 1000, 1000, 1001)]
    [InlineData(1000, 1000, 1000, 1001, 1000, 1000)]
    public void Caller_policy_rejects_root_and_set_id_states(int real, int effective, int saved, int realGroup, int effectiveGroup, int savedGroup)
    {
        Assert.Throws<PlatformNotSupportedException>(() => LdapWorkerDeployment.RequireCallerPolicy(
            (uint)real, (uint)effective, (uint)saved, (uint)realGroup, (uint)effectiveGroup, (uint)savedGroup, 0, 0, 0));
    }
    private const string ReceiptBridgeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // Public build-provenance pins only. No deployment files, native library or
    // credential source is read by these deterministic receipt-policy tests.
    private static JsonObject Composition() => new()
    {
        ["FormatVersion"] = 1, ["Contract"] = "adfl-restricted-file-gssapi-v1", ["NativeAbi"] = 4,
        ["NativeBridgeSha256"] = ReceiptBridgeHash,
        ["Inputs"] = new JsonObject
        {
            ["MitArchiveSha256"] = "b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35",
            ["CyrusArchiveSha256"] = "7ccfc6abd01ed67c1a0924b353e526f1b766b21f42d4562ee635a8ebfc5bb38c",
            ["OpenLdapArchiveSha256"] = "1794dbb7225516ae5fb21f3f9a19c0181f0ce33e9d0218e0f623b0a386578181",
            ["MitPluginSourceSha256"] = "86f737e2ffe69a587c53bddb36df3b103dc632eccc978a3fe0f69118f6524898",
            ["CyrusGssapiSourceSha256"] = "a105e8462e893f6f17f594e6997df6a4a275ef34e468c017dcbcb8933a096e59"
        },
        ["Sources"] = new JsonArray(new JsonObject { ["Path"] = "src/adfl_restricted.c", ["Sha256"] = ReceiptBridgeHash }),
        ["Archives"] = new JsonArray(new JsonObject { ["Path"] = "lib/libkrb5.a", ["Sha256"] = ReceiptBridgeHash })
    };
    [Fact]
    public void Composition_receipt_matches_contract_pins_and_exact_admitted_bridge()
    {
        var bytes = Encoding.UTF8.GetBytes(Composition().ToJsonString());
        VerifiedDeployment.ValidateComposition(bytes, ReceiptBridgeHash);
        Assert.Throws<PlatformNotSupportedException>(() => VerifiedDeployment.ValidateComposition(bytes, new string('b', 64)));
    }
    [Theory]
    [InlineData("contract")]
    [InlineData("abi")]
    [InlineData("format")]
    [InlineData("pin")]
    [InlineData("missing")]
    [InlineData("unknown")]
    [InlineData("empty-sources")]
    [InlineData("duplicate-path")]
    [InlineData("unsafe-path")]
    [InlineData("invalid-hash")]
    public void Composition_receipt_rejects_incompatible_or_ambiguous_provenance(string defect)
    {
        var receipt = Composition();
        switch (defect)
        {
            case "contract": receipt["Contract"] = "other-contract"; break;
            case "abi": receipt["NativeAbi"] = 2; break;
            case "format": receipt["FormatVersion"] = 2; break;
            case "pin": receipt["Inputs"]!["MitPluginSourceSha256"] = new string('b', 64); break;
            case "missing": receipt.Remove("Inputs"); break;
            case "unknown": receipt["Enable"] = true; break;
            case "empty-sources": receipt["Sources"] = new JsonArray(); break;
            case "duplicate-path": receipt["Sources"]!.AsArray().Add(receipt["Sources"]![0]!.DeepClone()); break;
            case "unsafe-path": receipt["Archives"]![0]!["Path"] = "../libkrb5.a"; break;
            case "invalid-hash": receipt["Sources"]![0]!["Sha256"] = "not-a-digest"; break;
        }
        Assert.ThrowsAny<Exception>(() => VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(receipt.ToJsonString()), ReceiptBridgeHash));
    }
    [Theory]
    [InlineData("\"NativeAbi\":4", "\"NativeAbi\":4,\"NativeAbi\":4")]
    [InlineData("\"Path\":\"src/adfl_restricted.c\"", "\"Path\":\"src/adfl_restricted.c\",\"Path\":\"src/adfl_restricted.c\"")]
    public void Composition_receipt_rejects_duplicate_fields(string from, string to)
    {
        var json = Composition().ToJsonString();
        Assert.Contains(from, json);
        Assert.Throws<InvalidDataException>(() => VerifiedDeployment.ValidateComposition(Encoding.UTF8.GetBytes(json.Replace(from, to, StringComparison.Ordinal)), ReceiptBridgeHash));
    }
    private static string Recipe() => JsonSerializer.Serialize(new
    {
        FormatVersion = 1, Version = "release-1",
        Roles = new { Dotnet = "dotnet/dotnet", HostAssembly = "host/host.dll", Supervisor = "native/worker.so", NativeBridge = "native/bridge.so" },
        Artifacts = new[] { "dotnet/dotnet", "host/host.dll", "native/worker.so", "native/bridge.so" }
            .Select(path => new { Path = path, Sha256 = new string('a', 64) }).ToArray()
    });
    [Fact]
    public void Manifest_requires_exact_roles_and_complete_distinct_inventory()
    {
        var manifest = LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(Recipe()));
        Assert.Equal("release-1", manifest.Version); Assert.Equal(4, manifest.Artifacts.Length);
        Assert.Equal("native/bridge.so", manifest.Roles.NativeBridge);
    }
    [Theory]
    [InlineData("\"FormatVersion\":1", "\"FormatVersion\":2")]
    [InlineData("\"FormatVersion\":1", "\"FormatVersion\":1,\"FormatVersion\":1")]
    [InlineData("\"Version\":\"release-1\"", "\"Version\":\"release-1\",\"Shell\":\"/bin/sh\"")]
    [InlineData("dotnet/dotnet", "../dotnet")]
    [InlineData("dotnet/dotnet", "/dotnet")]
    [InlineData("dotnet/dotnet", "dotnet//dotnet")]
    [InlineData("dotnet/dotnet", "dotnet/./dotnet")]
    [InlineData("native/worker.so", "native/bridge.so")]
    public void Manifest_rejects_ambiguity_unsafe_paths_and_duplicate_inventory(string from, string to)
    {
        Assert.ThrowsAny<Exception>(() => LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(Recipe().Replace(from, to, StringComparison.Ordinal))));
    }
    [Fact]
    public void Manifest_rejects_missing_role_and_invalid_digest()
    {
        var recipe = Recipe();
        Assert.Throws<InvalidDataException>(() => LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(recipe.Replace("\"NativeBridge\":\"native/bridge.so\"", "\"NativeBridge\":\"native/missing.so\"", StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() => LdapWorkerDeployment.Parse(Encoding.UTF8.GetBytes(recipe.Replace(new string('a', 64), new string('g', 64), StringComparison.Ordinal))));
    }
    [Fact]
    public void Writable_temporary_ancestry_never_admits_a_deployment()
    {
        if (!OperatingSystem.IsLinux()) return;
        // Only fresh test-owned files. On root test runners the caller policy
        // refuses first; on nonroot it must reject writable /tmp ancestry.
        var path = Path.Combine(Path.GetTempPath(), "adfl-deployment-negative-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            File.WriteAllText(Path.Combine(path, "manifest.json"), Recipe());
            Assert.ThrowsAny<Exception>(() => LdapWorkerDeployment.Validate(path));
        }
        finally { Directory.Delete(path, recursive: true); }
    }
}
