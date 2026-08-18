using System.ComponentModel;
using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

using EntrySecurityMasks = AdForLinux.DirectoryServices.SecurityMasks;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryOptionsTests
{
    private static DirectoryEntry Open(string dn) =>
        new(
            TestSettings.PathFor(dn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

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
    public void Unsupported_password_options_fail_when_configured()
    {
        using var entry = new DirectoryEntry();

        Assert.Equal(PasswordEncodingMethod.PasswordEncodingSsl, entry.Options.PasswordEncoding);
        Assert.Equal(636, entry.Options.PasswordPort);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.PasswordEncoding = (PasswordEncodingMethod)2);
        Assert.Throws<PlatformNotSupportedException>(
            () => entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingClear);
        Assert.Throws<PlatformNotSupportedException>(() => entry.Options.PasswordPort = 389);

        entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingSsl;
        entry.Options.PasswordPort = 636;
    }

    [Fact]
    public void Security_masks_reject_unknown_flags()
    {
        using var entry = new DirectoryEntry();

        entry.Options.SecurityMasks = EntrySecurityMasks.Owner | EntrySecurityMasks.Dacl;
        Assert.Equal(EntrySecurityMasks.Owner | EntrySecurityMasks.Dacl, entry.Options.SecurityMasks);
        Assert.Throws<InvalidEnumArgumentException>(
            () => entry.Options.SecurityMasks = (EntrySecurityMasks)0x10);
    }
}
