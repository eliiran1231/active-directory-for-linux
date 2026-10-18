using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Tests;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class OfflineExecutionGuardTests
{
    private static LdapConnectionOptions Options => new() { Host = "must-not-resolve.invalid" };

    [OfflineFact]
    public void Connection_creation_fails_before_native_handle_creation()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => LdapConnectionFactory.Create(Options)).Message);

    [OfflineFact]
    public void Connection_binding_fails_before_native_handle_creation()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => LdapConnectionFactory.CreateBound(Options)).Message);

    [OfflineFact]
    public void Identity_session_cannot_open_a_live_connection()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => new LdapIdentitySearchSession(Options)).Message);

    [OfflineFact]
    public void Cross_context_session_cannot_open_a_live_connection()
        => Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => new CrossContextSaveSession(Options)).Message);

    [OfflineFact]
    public void Accidentally_selected_live_read_test_fails_before_reading_endpoint_settings()
    {
        // Invoke the actual offending test body under the immutable offline guard.
        // Its first TestSettings access throws, before entry creation or any bind.
        Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => new DirectoryEntryReadTests().Reads_a_string_property()).Message);
        Assert.Equal(OfflineTestGuard.Message,
            Assert.Throws<InvalidOperationException>(() => TestSettings.CreatePrincipalContext()).Message);
    }
}
