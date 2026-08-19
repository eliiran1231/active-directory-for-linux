using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryMoveTests
{
    private const string SourceDn = "CN=child,OU=Source,DC=example,DC=test";
    private const string DestinationDn = "OU=Destination,DC=example,DC=test";

    [Theory]
    [InlineData("LDAP://destination.example.test:389/OU=Destination,DC=example,DC=test", "bind", "secret", AuthenticationTypes.None)]
    [InlineData("LDAP://source.example.test:1389/OU=Destination,DC=example,DC=test", "bind", "secret", AuthenticationTypes.None)]
    [InlineData("LDAP://source.example.test:389/OU=Destination,DC=example,DC=test", "bind", "secret", AuthenticationTypes.SecureSocketsLayer)]
    [InlineData("LDAP://source.example.test:389/OU=Destination,DC=example,DC=test", "other-bind", "secret", AuthenticationTypes.None)]
    [InlineData("LDAP://source.example.test:389/OU=Destination,DC=example,DC=test", "bind", "other-secret", AuthenticationTypes.None)]
    public void MoveTo_rejects_a_different_connection_context_before_binding(
        string destinationPath,
        string username,
        string password,
        AuthenticationTypes authenticationType)
    {
        using var source = new DirectoryEntry(
            $"LDAP://source.example.test:389/{SourceDn}",
            "bind",
            "secret",
            AuthenticationTypes.None);
        using var destination = new DirectoryEntry(
            destinationPath,
            username,
            password,
            authenticationType);

        var error = Assert.Throws<PlatformNotSupportedException>(() => source.MoveTo(destination));

        Assert.Contains("different LDAP connection contexts", error.Message, StringComparison.Ordinal);
        Assert.Contains("No LDAP request was sent", error.Message, StringComparison.Ordinal);
        Assert.Equal(SourceDn, source.DistinguishedName);
    }

    [Fact]
    public void MoveTo_with_new_name_rejects_a_different_server_before_binding()
    {
        using var source = new DirectoryEntry(
            $"LDAP://source.example.test:389/{SourceDn}",
            "bind",
            "secret",
            AuthenticationTypes.None);
        using var destination = new DirectoryEntry(
            $"LDAP://destination.example.test:389/{DestinationDn}",
            "bind",
            "secret",
            AuthenticationTypes.None);

        var error = Assert.Throws<PlatformNotSupportedException>(
            () => source.MoveTo(destination, "CN=renamed"));

        Assert.Contains("different LDAP connection contexts", error.Message, StringComparison.Ordinal);
        Assert.Equal(SourceDn, source.DistinguishedName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void MoveTo_rejects_invalid_names_while_CopyTo_reports_ADSI_not_implemented(string newName)
    {
        using var source = new DirectoryEntry(
            $"LDAP://source.example.test:389/{SourceDn}",
            "bind",
            "secret",
            AuthenticationTypes.None);
        using var destination = new DirectoryEntry(
            $"LDAP://source.example.test:389/{DestinationDn}",
            "bind",
            "secret",
            AuthenticationTypes.None);

        Assert.Throws<ArgumentException>(() => source.MoveTo(destination, newName));
        Assert.Throws<NotImplementedException>(() => source.CopyTo(destination, newName));
    }

    [Fact]
    public void MoveTo_same_connection_moves_and_renames_the_entry()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sourceOuName = $"adfl-move-source-{suffix}";
        var destinationOuName = $"adfl-move-destination-{suffix}";
        var groupName = $"adfl-move-group-{suffix}";
        var renamedGroupName = $"adfl-moved-group-{suffix}";
        var sourceOuDn = $"OU={sourceOuName},{TestSettings.BaseDn}";
        var destinationOuDn = $"OU={destinationOuName},{TestSettings.BaseDn}";
        var sourceGroupDn = $"CN={groupName},{sourceOuDn}";
        var destinationGroupDn = $"CN={renamedGroupName},{destinationOuDn}";

        try
        {
            using (var testContainer = Open(TestSettings.BaseDn))
            {
                using var sourceOu = testContainer.Children.Add($"OU={sourceOuName}", "organizationalUnit");
                sourceOu.CommitChanges();

                using var destinationOu = testContainer.Children.Add($"OU={destinationOuName}", "organizationalUnit");
                destinationOu.CommitChanges();
            }

            using (var sourceOu = Open(sourceOuDn))
            using (var group = sourceOu.Children.Add($"CN={groupName}", "group"))
            {
                group.Properties["sAMAccountName"].Value = groupName;
                group.CommitChanges();
            }

            using (var group = Open(sourceGroupDn))
            using (var destinationOu = Open(destinationOuDn))
            {
                group.MoveTo(destinationOu, $"CN={renamedGroupName}");
                Assert.Equal(destinationGroupDn, group.DistinguishedName);
            }

            using var reopened = Open(destinationGroupDn);
            Assert.Equal(groupName, reopened.Properties["sAMAccountName"].Value);
        }
        finally
        {
            SafeDelete(destinationOuDn);
            SafeDelete(sourceOuDn);
        }
    }

    [Fact]
    public void MoveTo_null_name_matches_the_parent_only_overload()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sourceOuName = $"adfl-null-move-source-{suffix}";
        var destinationOuName = $"adfl-null-move-target-{suffix}";
        var oneArgumentName = $"adfl-null-move-one-{suffix}";
        var explicitNullName = $"adfl-null-move-null-{suffix}";
        var sourceOuDn = $"OU={sourceOuName},{TestSettings.BaseDn}";
        var destinationOuDn = $"OU={destinationOuName},{TestSettings.BaseDn}";
        var oneArgumentDn = $"CN={oneArgumentName},{sourceOuDn}";
        var explicitNullDn = $"CN={explicitNullName},{sourceOuDn}";

        try
        {
            using (var domain = Open(TestSettings.BaseDn))
            {
                using var sourceOu = domain.Children.Add($"OU={sourceOuName}", "organizationalUnit");
                sourceOu.CommitChanges();
                using var destinationOu = domain.Children.Add($"OU={destinationOuName}", "organizationalUnit");
                destinationOu.CommitChanges();
            }

            using (var source = Open(sourceOuDn))
            {
                using var oneArgument = source.Children.Add($"CN={oneArgumentName}", "group");
                oneArgument.Properties["sAMAccountName"].Value = oneArgumentName;
                oneArgument.CommitChanges();
                using var explicitNull = source.Children.Add($"CN={explicitNullName}", "group");
                explicitNull.Properties["sAMAccountName"].Value = explicitNullName;
                explicitNull.CommitChanges();
            }

            using var destination = Open(destinationOuDn);
            using var movedWithOneArgument = Open(oneArgumentDn);
            using var movedWithNull = Open(explicitNullDn);

            movedWithOneArgument.MoveTo(destination);
            movedWithNull.MoveTo(destination, null);

            Assert.Equal($"CN={oneArgumentName},{destinationOuDn}", movedWithOneArgument.DistinguishedName);
            Assert.Equal($"CN={explicitNullName},{destinationOuDn}", movedWithNull.DistinguishedName);
            Assert.Equal($"CN={oneArgumentName}", movedWithOneArgument.Name);
            Assert.Equal($"CN={explicitNullName}", movedWithNull.Name);
        }
        finally
        {
            SafeDelete(destinationOuDn);
            SafeDelete(sourceOuDn);
        }
    }

    private static DirectoryEntry Open(string dn) =>
        new(
            TestSettings.PathFor(dn),
            TestSettings.BindDn,
            TestSettings.BindPassword,
            TestSettings.UseTls ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.None);

    private static void SafeDelete(string dn)
    {
        try
        {
            using var entry = Open(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup.
        }
    }
}
