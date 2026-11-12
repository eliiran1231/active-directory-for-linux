using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Xunit.Abstractions;

namespace AdForLinux.DifferentialTests;

// Recording is output-only: callers pass already-observed detached values.
// Never pass directory contents, connection settings, credentials or exceptions
// themselves. Keep stable exception type/parameter fields, not localized messages.
internal static class DifferentialRecording
{
    internal const string Prefix = "ADFL_DIFFERENTIAL_OBSERVATION_V1: ";

    internal static void Write(ITestOutputHelper output, string caseId, object? microsoft, object? adForLinux)
    {
        var assembly = typeof(DifferentialRecording).Assembly;
        var provenance = new
        {
            os = RuntimeInformation.OSDescription,
            architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            runtime = RuntimeInformation.FrameworkDescription,
            target = assembly.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName,
            sdk = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .SingleOrDefault(attribute => attribute.Key == "BuildSdkVersion")?.Value,
            commit = Environment.GetEnvironmentVariable("GITHUB_SHA")
                ?? assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            microsoftDirectoryServices = typeof(System.DirectoryServices.DirectoryEntry).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            microsoftAccountManagement = typeof(System.DirectoryServices.AccountManagement.Principal).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
        };
        output.WriteLine(Prefix + JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            caseId,
            source = "microsoft-windows-differential",
            provenance,
            microsoft,
            adForLinux,
        }));
    }
}
