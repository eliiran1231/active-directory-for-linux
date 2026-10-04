using System.ComponentModel;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

using EntrySecurityMasks = AdForLinux.DirectoryServices.SecurityMasks;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryOptionsTests
{
    [Theory]
    [InlineData("close")]
    [InlineData("path")]
    [InlineData("username")]
    [InlineData("password")]
    [InlineData("authentication")]
    public void Rebinding_resets_retained_options_to_fresh_entry_state(string operation)
    {
        using var fresh = new DirectoryEntry();
        using var entry = new DirectoryEntry();
        var retained = entry.Options;
        retained.PageSize = 17;
        retained.SecurityMasks = EntrySecurityMasks.Owner;
        retained.PasswordPort = 1636;
        retained.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingClear;
        retained.Referral = ReferralChasingOption.None;

        // Changing referrals recreates the transport, not the logical binding.
        Assert.Equal(17, retained.PageSize);
        Assert.Equal(EntrySecurityMasks.Owner, retained.SecurityMasks);
        switch (operation)
        {
            case "close": entry.Close(); break;
            case "path": entry.Path = "LDAP://localhost:1/DC=test"; break;
            case "username": entry.Username = "changed"; break;
            case "password": entry.Password = "changed"; break;
            case "authentication": entry.AuthenticationType = AuthenticationTypes.Anonymous; break;
        }

        Assert.Same(retained, entry.Options);
        Assert.Equal(fresh.Options.PageSize, retained.PageSize);
        Assert.Equal(EntrySecurityMasks.Owner | EntrySecurityMasks.Group | EntrySecurityMasks.Dacl,
            retained.SecurityMasks);
        Assert.Equal(fresh.Options.SecurityMasks, entry.Options.SecurityMasks);
        Assert.Equal(fresh.Options.PasswordPort, retained.PasswordPort);
        Assert.Equal(fresh.Options.PasswordEncoding, retained.PasswordEncoding);
        Assert.Equal(fresh.Options.Referral, retained.Referral);

        // Set immediately after Close, without a getter, then reset again.
        entry.Close();
        retained.PageSize = 31;
        retained.SecurityMasks = EntrySecurityMasks.None;
        Assert.Equal(31, entry.Options.PageSize);
        Assert.Equal(EntrySecurityMasks.None, entry.Options.SecurityMasks);
        entry.Close();
        entry.Close();
        Assert.Equal(fresh.Options.PageSize, retained.PageSize);
        Assert.Equal(fresh.Options.SecurityMasks, retained.SecurityMasks);

        entry.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = retained.PageSize);
        Assert.Throws<ObjectDisposedException>(() => retained.PageSize = 1);
        Assert.Throws<ArgumentException>(() => retained.PageSize = -1);
        Assert.Throws<ObjectDisposedException>(() => _ = retained.SecurityMasks);
        Assert.Throws<ObjectDisposedException>(() => retained.SecurityMasks = EntrySecurityMasks.None);
        Assert.Throws<InvalidEnumArgumentException>(() => retained.SecurityMasks = (EntrySecurityMasks)16);
    }

    private static DirectoryEntry Open(string dn) =>
        new(
            TestSettings.PathFor(dn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    [Fact]
    public void Close_resets_options_and_next_connection_uses_new_assignments()
    {
        using var entry = Open(TestSettings.BaseDn);
        using var fresh = Open(TestSettings.BaseDn);
        var retained = entry.Options;
        retained.PageSize = 17;
        retained.SecurityMasks = EntrySecurityMasks.Owner;
        var originalConnection = entry.GetConnection();

        entry.Close();
        Assert.Equal(fresh.Options.PageSize, retained.PageSize);
        Assert.Equal(fresh.Options.SecurityMasks, entry.Options.SecurityMasks);
        retained.PageSize = 31;
        retained.SecurityMasks = EntrySecurityMasks.Dacl;
        retained.Referral = ReferralChasingOption.None;
        var rebound = entry.GetConnection();
        Assert.NotSame(originalConnection, rebound);
        Assert.Equal(31, retained.PageSize);
        Assert.Equal(EntrySecurityMasks.Dacl, entry.Options.SecurityMasks);
        Assert.Equal(ReferralChasingOptions.None, rebound.SessionOptions.ReferralChasing);
    }

    [Fact]
    public void Page_size_rejects_negative_values()
    {
        using var entry = new DirectoryEntry();

        Assert.Throws<ArgumentException>(() => entry.Options.PageSize = -1);
        Assert.Equal(0, entry.Options.PageSize);

        entry.Options.PageSize = 128;
        Assert.Equal(128, entry.Options.PageSize);
    }

    [Fact]
    public void Referral_rejects_unknown_values_and_maps_supported_values()
    {
        using var entry = new DirectoryEntry();

        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.Referral = (ReferralChasingOption)1);

        using var connection = new LdapConnection(new LdapDirectoryIdentifier("localhost"));
        LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.None);
        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);

        LdapConnectionFactory.ConfigureReferralChasing(connection, ReferralChasingOption.External);
        Assert.Equal(
            OperatingSystem.IsWindows() ? ReferralChasingOptions.External : ReferralChasingOptions.All,
            connection.SessionOptions.ReferralChasing);
    }

    [Fact]
    public void Referral_is_applied_to_entry_ldap_operations()
    {
        using var entry = Open(TestSettings.BaseDn);
        entry.Options.Referral = ReferralChasingOption.None;

        var withoutChasing = entry.GetConnection();
        Assert.Equal(ReferralChasingOptions.None, withoutChasing.SessionOptions.ReferralChasing);

        entry.Options.Referral = ReferralChasingOption.External;
        var withChasing = entry.GetConnection();

        Assert.NotSame(withoutChasing, withChasing);
        Assert.Equal(
            OperatingSystem.IsWindows() ? ReferralChasingOptions.External : ReferralChasingOptions.All,
            withChasing.SessionOptions.ReferralChasing);
    }

    [Fact]
    public void Password_options_store_requested_values_and_preserve_enum_validation()
    {
        using var entry = new DirectoryEntry();

        Assert.Equal(PasswordEncodingMethod.PasswordEncodingSsl, entry.Options.PasswordEncoding);
        Assert.Equal(636, entry.Options.PasswordPort);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.PasswordEncoding = (PasswordEncodingMethod)2);
        entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingClear;
        entry.Options.PasswordPort = 1636;
        Assert.Equal(PasswordEncodingMethod.PasswordEncodingClear, entry.Options.PasswordEncoding);
        Assert.Equal(1636, entry.Options.PasswordPort);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.PasswordEncoding = (PasswordEncodingMethod)(-1));
        Assert.Equal(PasswordEncodingMethod.PasswordEncodingClear, entry.Options.PasswordEncoding);

        entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingSsl;
        entry.Options.PasswordPort = 636;
        Assert.Equal(PasswordEncodingMethod.PasswordEncodingSsl, entry.Options.PasswordEncoding);
        Assert.Equal(636, entry.Options.PasswordPort);
    }

    [Theory]
    [InlineData(PasswordEncodingMethod.PasswordEncodingClear, 636, "Clear-text")]
    [InlineData(PasswordEncodingMethod.PasswordEncodingSsl, 1636, "port")]
    [InlineData(PasswordEncodingMethod.PasswordEncodingSsl, 389, "port")]
    public void Unsupported_password_options_fail_before_password_operations_bind(
        PasswordEncodingMethod encoding, int port, string message)
    {
        using var entry = new DirectoryEntry("LDAP://localhost:1/CN=test");
        entry.Options.PasswordEncoding = encoding;
        entry.Options.PasswordPort = port;

        var resetError = Assert.Throws<PlatformNotSupportedException>(
            () => entry.ReplaceAttributeImmediate("UNICODEpwd", new byte[] { 1 }));
        var changeError = Assert.Throws<PlatformNotSupportedException>(
            () => entry.ChangePasswordImmediate(new byte[] { 1 }, new byte[] { 2 }));
        Assert.Contains(message, resetError.Message, StringComparison.Ordinal);
        Assert.Contains(message, changeError.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SetPassword")]
    [InlineData("ChangePassword")]
    public void Password_options_do_not_enable_unsupported_ADSI_password_invocation(string method)
    {
        using var entry = new DirectoryEntry();
        entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingClear;
        entry.Options.PasswordPort = 1636;

        Assert.Throws<PlatformNotSupportedException>(() => entry.Invoke(method, "old", "new"));
    }

    [Fact]
    public void Security_masks_reject_unknown_flags()
    {
        using var entry = new DirectoryEntry();

        entry.Options.SecurityMasks = EntrySecurityMasks.Owner | EntrySecurityMasks.Dacl;
        Assert.Equal(EntrySecurityMasks.Owner | EntrySecurityMasks.Dacl, entry.Options.SecurityMasks);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.SecurityMasks = (EntrySecurityMasks)0x10);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.SecurityMasks = (EntrySecurityMasks)(-1));
    }

    [Fact]
    public void Current_server_name_binds_and_reports_the_server_from_root_dse()
    {
        using var entry = Open(TestSettings.BaseDn);
        using var connection = LdapConnectionFactory.CreateBound(entry.BuildOptions());
        var expected = RootDse.GetConnectedServerName(connection);

        Assert.Equal(expected, entry.Options.GetCurrentServerName(), ignoreCase: true);
    }

    [Fact]
    public void Mutual_authentication_status_is_explicitly_unavailable_after_binding()
    {
        using var entry = Open(TestSettings.BaseDn);

        var exception = Assert.Throws<PlatformNotSupportedException>(
            () => entry.Options.IsMutuallyAuthenticated());

        Assert.Contains("does not expose", exception.Message, StringComparison.Ordinal);
        Assert.NotNull(entry.GetConnection());
    }

    [Fact]
    public void User_name_query_quota_is_not_available_over_ldap()
    {
        using var entry = new DirectoryEntry();

        var exception = Assert.Throws<PlatformNotSupportedException>(
            () => entry.Options.SetUserNameQueryQuota("CONTOSO\\alice"));

        Assert.Contains("requires ADSI", exception.Message, StringComparison.Ordinal);
        Assert.Contains("not available over LDAP", exception.Message, StringComparison.Ordinal);
    }
}
