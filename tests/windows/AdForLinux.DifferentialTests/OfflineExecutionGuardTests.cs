using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Tests;
using Xunit;

namespace AdForLinux.DifferentialTests;

public class OfflineExecutionGuardTests
{
    [OfflineFact]
    public void Live_fixture_constructor_fails_before_provisioning_or_cleanup()
        => Assert.Equal(SuiteCapture.Expected(OfflineTestGuard.Message, "assert-equal-expected", 11),
            SuiteCapture.Expected(Assert.Throws<InvalidOperationException>(() => new TestDataFixture()).Message, "assert-equal-actual", 11));

    [OfflineFact]
    public void Live_settings_fail_before_reading_environment_values()
        => Assert.Equal(SuiteCapture.Expected(OfflineTestGuard.Message, "assert-equal-expected", 16),
            SuiteCapture.Expected(Assert.Throws<InvalidOperationException>(() => _ = DifferentialSettings.Host).Message, "assert-equal-actual", 16));
}
