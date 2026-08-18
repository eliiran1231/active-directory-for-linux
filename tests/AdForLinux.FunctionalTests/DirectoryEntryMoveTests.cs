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
