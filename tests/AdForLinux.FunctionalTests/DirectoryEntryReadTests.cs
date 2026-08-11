using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

/// <summary>
/// Step 3: read objects with DirectoryEntry against smblds.
/// </summary>
public class DirectoryEntryReadTests
{
    private static DirectoryEntry Open(string dn) =>
        new(TestSettings.PathFor(dn), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    [Fact]
    public void Reads_a_string_property()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
    }

    [Fact]
    public void Parameterless_entry_can_be_configured_before_it_binds()
    {
        using var entry = new DirectoryEntry();

        Assert.Equal(string.Empty, entry.Path);
        Assert.Equal(AuthenticationTypes.Secure, entry.AuthenticationType);

        entry.Path = TestSettings.PathFor(TestSettings.AdministratorDn);
        entry.AuthenticationType = AuthenticationTypes.SecureSocketsLayer;
        entry.Username = TestSettings.BindDn;
        entry.Password = TestSettings.BindPassword;

        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
    }

    [Fact]
    public void Adsi_only_operations_fail_with_a_clear_platform_exception()
    {
        using var entry = new DirectoryEntry();

        Assert.Equal(string.Empty, entry.Path);
        Assert.Equal(AuthenticationTypes.Secure, entry.AuthenticationType);
        Assert.Equal(PasswordEncodingMethod.PasswordEncodingSsl, entry.Options.PasswordEncoding);
        Assert.Throws<PlatformNotSupportedException>(() => entry.InvokeGet("objectClass"));
        Assert.Throws<PlatformNotSupportedException>(() => entry.CopyTo(entry));
        Assert.Throws<PlatformNotSupportedException>(() => _ = entry.NativeObject);
        Assert.Throws<PlatformNotSupportedException>(() => _ = entry.SchemaEntry);
    }

    [Fact]
    public void Name_is_the_relative_dn()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        Assert.Equal("CN=Administrator", entry.Name);
    }

    [Fact]
    public void Path_round_trips()
    {
        var path = TestSettings.PathFor(TestSettings.AdministratorDn);
        using var entry = new DirectoryEntry(path);

        Assert.Equal(path, entry.Path);
        Assert.Equal(TestSettings.AdministratorDn, entry.DistinguishedName);
    }

    [Fact]
    public void SchemaClassName_is_the_most_specific_class()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        // objectClass is top, person, organizationalPerson, user -> "user".
        Assert.Equal("user", entry.SchemaClassName);
    }

    [Fact]
    public void Multi_valued_property_exposes_all_values()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        var classes = entry.Properties["objectClass"];
        Assert.True(classes.Count >= 4);
        Assert.Contains("user", classes.Cast<object>().Select(v => v.ToString()));
    }

    [Fact]
    public void Guid_is_read_from_objectGuid()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        Assert.NotEqual(Guid.Empty, entry.Guid);
    }

    [Fact]
    public void Default_properties_include_the_security_descriptor()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        var descriptor = entry.Properties["nTSecurityDescriptor"];

        Assert.NotEmpty(descriptor);
        Assert.IsType<byte[]>(descriptor.Value);
    }

    [Fact]
    public void Missing_property_returns_empty_without_throwing()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        var missing = entry.Properties["thisAttributeDoesNotExist"];
        Assert.Equal(0, missing.Count);
        Assert.Null(missing.Value);
        Assert.False(entry.Properties.Contains("thisAttributeDoesNotExist2"));
    }

    [Fact]
    public void Domain_root_reads_its_object_class()
    {
        using var entry = Open(TestSettings.BaseDn);

        var classes = entry.Properties["objectClass"].Cast<object>().Select(v => v.ToString());
        Assert.Contains("domainDNS", classes);
    }
}
