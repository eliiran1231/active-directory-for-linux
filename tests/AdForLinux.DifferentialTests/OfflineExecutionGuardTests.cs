using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Tests;
using Xunit;

namespace AdForLinux.DifferentialTests;

public class OfflineExecutionGuardTests
{
    [OfflineFact]
    public void Live_fixture_constructor_fails_before_provisioning_or_cleanup()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => new TestDataFixture()).Message);

    [OfflineFact]
    public void Live_settings_fail_before_reading_environment_values()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => _ = DifferentialSettings.Host).Message);
}
