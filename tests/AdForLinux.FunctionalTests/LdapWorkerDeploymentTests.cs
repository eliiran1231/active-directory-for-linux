using System.Text;
using System.Text.Json;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class LdapWorkerDeploymentTests
{
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
