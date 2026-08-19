using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
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
    public void Null_paths_are_normalized_to_an_empty_unbound_path()
    {
        using var pathOnly = new DirectoryEntry((string?)null);
        using var credentials = new DirectoryEntry(null, "user", "password");
        using var authentication = new DirectoryEntry(
            null, "user", "password", AuthenticationTypes.Anonymous);

        Assert.Equal(string.Empty, pathOnly.Path);
        Assert.Equal(string.Empty, credentials.Path);
        Assert.Equal(string.Empty, authentication.Path);

        using var bound = new DirectoryEntry("LDAP://server/DC=example,DC=test");
        bound.Path = null;

        Assert.Equal(string.Empty, bound.Path);
        Assert.Equal(string.Empty, bound.DistinguishedName);
        Assert.Null(bound.ServerHost);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("  \t  ")]
    public void Empty_and_whitespace_paths_remain_distinct_from_null(string path)
    {
        using var constructed = new DirectoryEntry(path);
        using var assigned = new DirectoryEntry();

        assigned.Path = path;

        Assert.Equal(path, constructed.Path);
        Assert.Equal(path, assigned.Path);
        Assert.Null(constructed.ServerHost);
        Assert.Null(assigned.ServerHost);
        Assert.Throws<NotSupportedException>(() => constructed.BuildOptions());
        Assert.Throws<NotSupportedException>(() => assigned.BuildOptions());
    }

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
        Assert.Throws<PlatformNotSupportedException>(() => _ = entry.NativeObject);
    }

    [Fact]
    public void Name_is_the_relative_dn()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        Assert.Equal("CN=Administrator", entry.Name);
    }

    [Theory]
    [InlineData(@"CN=hello\,world,OU=Users,DC=example,DC=com", @"CN=hello\,world")]
    [InlineData(@"CN=hello\\,OU=Users,DC=example,DC=com", @"CN=hello\\")]
    [InlineData(@"CN=hello\\\,world,OU=Users,DC=example,DC=com", @"CN=hello\\\,world")]
    public void Name_honors_odd_and_even_backslash_runs(string distinguishedName, string expectedName)
    {
        Assert.Equal(expectedName, LdapDistinguishedName.RelativeName(distinguishedName));
    }

    [Theory]
    [InlineData(@"CN=hello\,world,OU=Users,DC=example,DC=com")]
    [InlineData(@"CN=hello\\,OU=Users,DC=example,DC=com")]
    [InlineData(@"CN=hello\\\,world,OU=Users,DC=example,DC=com")]
    public void Parent_honors_odd_and_even_backslash_runs(string distinguishedName)
    {
        Assert.Equal("OU=Users,DC=example,DC=com", LdapDistinguishedName.Parent(distinguishedName));
    }

    [Fact]
    public void Parent_binds_and_inherits_connection_and_cache_settings()
    {
        using var entry = Open(TestSettings.AdministratorDn);
        entry.UsePropertyCache = false;

        using var parent = entry.Parent;

        Assert.NotNull(parent);
        Assert.Equal($"CN=Users,{TestSettings.BaseDn}", parent.DistinguishedName);
        Assert.Equal("CN=Users", parent.Name);
        Assert.Equal(entry.UsePropertyCache, parent.UsePropertyCache);
        Assert.Equal(entry.Username, parent.Username);
        Assert.Equal(entry.AuthenticationType, parent.AuthenticationType);
        Assert.Equal(entry.BuildOptions().BindPassword, parent.BuildOptions().BindPassword);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Name_and_parent_bind_before_deriving_values(bool readName)
    {
        var missingDn = $"CN=issue107-missing-{Guid.NewGuid():N},{TestSettings.BaseDn}";
        using var entry = Open(missingDn);

        var exception = Assert.Throws<DirectoryServicesCOMException>(() =>
        {
            if (readName)
            {
                _ = entry.Name;
            }
            else
            {
                _ = entry.Parent;
            }
        });

        Assert.Equal(unchecked((int)0x80072030), exception.ErrorCode);
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
    public void SchemaEntry_resolves_the_most_specific_class_from_the_schema_partition()
    {
        using var entry = Open(TestSettings.AdministratorDn);
        using var schemaEntry = entry.SchemaEntry;

        Assert.Equal("classSchema", schemaEntry.SchemaClassName);
        Assert.Equal("user", schemaEntry.Properties["lDAPDisplayName"].Value);
        Assert.EndsWith(",CN=Schema,CN=Configuration," + TestSettings.BaseDn,
            schemaEntry.DistinguishedName, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(entry.UsePropertyCache, schemaEntry.UsePropertyCache);
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
    public void Partial_refresh_replaces_only_requested_cached_properties()
    {
        using var entry = Open(TestSettings.AdministratorDn);
        var properties = entry.Properties;
        var requestedBefore = properties["sAMAccountName"];
        var unrelatedBefore = properties["objectClass"];
        var missingBefore = properties["thisAttributeDoesNotExist"];
        var requestedValueFromServer = requestedBefore.Value;

        requestedBefore.Value = "staged account name";
        unrelatedBefore.Value = "staged object class";

        entry.RefreshCache(new[] { "SAMACCOUNTNAME", "sAMAccountName", "thisAttributeDoesNotExist" });

        Assert.Same(properties, entry.Properties);
        Assert.NotSame(requestedBefore, entry.Properties["sAMAccountName"]);
        Assert.Equal(requestedValueFromServer, entry.Properties["sAMAccountName"].Value);
        Assert.Equal("staged account name", requestedBefore.Value);
        Assert.Same(unrelatedBefore, entry.Properties["objectClass"]);
        Assert.Equal("staged object class", entry.Properties["objectClass"].Value);
        Assert.NotSame(missingBefore, entry.Properties["thisAttributeDoesNotExist"]);
        Assert.Null(entry.Properties["thisAttributeDoesNotExist"].Value);

        entry.RefreshCache(Array.Empty<string>());

        Assert.Same(properties, entry.Properties);
        Assert.Same(unrelatedBefore, entry.Properties["objectClass"]);
        Assert.Equal("staged object class", entry.Properties["objectClass"].Value);
    }

    [Fact]
    public void Domain_root_reads_its_object_class()
    {
        using var entry = Open(TestSettings.BaseDn);

        var classes = entry.Properties["objectClass"].Cast<object>().Select(v => v.ToString());
        Assert.Contains("domainDNS", classes);
    }
}
