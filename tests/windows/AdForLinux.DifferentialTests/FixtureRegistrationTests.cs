using Xunit;
using Xunit.Abstractions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AdForLinux.DifferentialTests;

public class FixtureRegistrationTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> TestDataFixtureConsumers =>
        typeof(TestDataFixture).Assembly.GetTypes()
            .Where(type => !type.IsAbstract && type.GetConstructors().Any(constructor =>
                constructor.GetParameters().Any(parameter =>
                    parameter.ParameterType == typeof(TestDataFixture))))
            .OrderBy(type => type.FullName)
            .Select(type => new object[] { type });

    // Check registration without constructing fixtures or connecting to AD.
    // Missing registration otherwise fails only after deploying to the lab.
    [Theory]
    [MemberData(nameof(TestDataFixtureConsumers))]
    public void Test_data_consumers_register_their_class_fixture(Type testClass)
    {
        // Keep reproduction metadata in each target's TRX without requiring a
        // special runner step, credentials, or another directory operation.
        var assembly = typeof(FixtureRegistrationTests).Assembly;
        output.WriteLine($"OS: {RuntimeInformation.OSDescription}; architecture: {RuntimeInformation.ProcessArchitecture}");
        output.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription}; target: {assembly.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName}");
        output.WriteLine($"SDK: {assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(attribute => attribute.Key == "BuildSdkVersion").Value}");
        output.WriteLine($"Commit/build: {Environment.GetEnvironmentVariable("GITHUB_SHA") ?? assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion}");
        output.WriteLine($"Microsoft DirectoryServices: {typeof(System.DirectoryServices.DirectoryEntry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion}");
        output.WriteLine($"Microsoft AccountManagement: {typeof(System.DirectoryServices.AccountManagement.Principal).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion}");
        Assert.True(typeof(IClassFixture<TestDataFixture>).IsAssignableFrom(testClass),
            $"{testClass.FullName} must implement IClassFixture<TestDataFixture>.");
    }
}
