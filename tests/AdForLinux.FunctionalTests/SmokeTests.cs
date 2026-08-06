using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 1 smoke test: proves the build/test pipeline runs on both
/// net8.0 and net10.0. Real LDAP tests arrive in step 2.
/// </summary>
public class SmokeTests
{
    [Fact]
    public void Both_libraries_are_referenced()
    {
        Assert.Equal("AdForLinux.DirectoryServices",
            typeof(DirectoryEntry).Assembly.GetName().Name);
        Assert.Equal("AdForLinux.DirectoryServices.AccountManagement",
            typeof(PrincipalContext).Assembly.GetName().Name);
    }

    [Fact]
    public void Runtime_is_net8_or_net10()
    {
        var version = Environment.Version;
        Assert.True(version.Major is 8 or 10, $"unexpected runtime {version}");
    }
}
