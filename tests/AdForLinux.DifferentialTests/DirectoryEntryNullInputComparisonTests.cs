using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public class DirectoryEntryNullInputComparisonTests
{
    [Fact]
    public void Null_path_constructors_match_microsoft()
    {
        using var msPathOnly = new Ms.DirectoryEntry((string?)null);
        using var ourPathOnly = new Ours.DirectoryEntry((string?)null);
        using var msCredentials = new Ms.DirectoryEntry(null, "user", "password");
        using var ourCredentials = new Ours.DirectoryEntry(null, "user", "password");
        using var msAuthentication = new Ms.DirectoryEntry(
            null, "user", "password", Ms.AuthenticationTypes.Anonymous);
        using var ourAuthentication = new Ours.DirectoryEntry(
            null, "user", "password", Ours.AuthenticationTypes.Anonymous);

        new Comparison("DirectoryEntry null path constructors")
            .Check("path-only Path", msPathOnly.Path, ourPathOnly.Path)
            .Check("credential Path", msCredentials.Path, ourCredentials.Path)
            .Check("authentication Path", msAuthentication.Path, ourAuthentication.Path)
            .Assert();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("  \t  ")]
    public void Path_assignment_matches_microsoft_from_bound_and_unbound_states(string? path)
    {
        using var msUnbound = new Ms.DirectoryEntry();
        using var ourUnbound = new Ours.DirectoryEntry();
        using var msBound = new Ms.DirectoryEntry("LDAP://server/DC=example,DC=test");
        using var ourBound = new Ours.DirectoryEntry("LDAP://server/DC=example,DC=test");

        msUnbound.Path = path;
        ourUnbound.Path = path;
        msBound.Path = path;
        ourBound.Path = path;

        new Comparison($"DirectoryEntry Path assignment ({Show(path)})")
            .Check("unbound Path", msUnbound.Path, ourUnbound.Path)
            .Check("previously bound Path", msBound.Path, ourBound.Path)
            .Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Null_move_and_copy_names_match_parent_only_overloads(bool passNullToMicrosoft)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var rootName = $"adfl-null-{suffix}";
        var rootDn = $"OU={rootName},{DifferentialSettings.BaseDn}";
        var msSourceDn = $"OU=ms-source,{rootDn}";
        var ourSourceDn = $"OU=our-source,{rootDn}";
        var msDestinationDn = $"OU=ms-destination,{rootDn}";
        var ourDestinationDn = $"OU=our-destination,{rootDn}";

        try
        {
            using (var domain = MicrosoftEntry(DifferentialSettings.BaseDn))
            using (var root = domain.Children.Add($"OU={rootName}", "organizationalUnit"))
            {
                root.CommitChanges();
            }

            using (var root = MicrosoftEntry(rootDn))
            {
                CreateOu(root, "OU=ms-source");
                CreateOu(root, "OU=our-source");
                CreateOu(root, "OU=ms-destination");
                CreateOu(root, "OU=our-destination");
            }

            using (var msSource = MicrosoftEntry(msSourceDn))
            using (var ourSource = MicrosoftEntry(ourSourceDn))
            {
                CreateOu(msSource, "OU=move-child");
                CreateOu(msSource, "OU=copy-child");
                CreateOu(ourSource, "OU=move-child");
                CreateOu(ourSource, "OU=copy-child");
            }

            using var msMove = MicrosoftEntry($"OU=move-child,{msSourceDn}");
            using var ourMove = OurEntry($"OU=move-child,{ourSourceDn}");
            using var msCopySource = MicrosoftEntry($"OU=copy-child,{msSourceDn}");
            using var ourCopySource = OurEntry($"OU=copy-child,{ourSourceDn}");
            using var msDestination = MicrosoftEntry(msDestinationDn);
            using var ourDestination = OurEntry(ourDestinationDn);

            if (passNullToMicrosoft)
            {
                msMove.MoveTo(msDestination, null);
                ourMove.MoveTo(ourDestination);
            }
            else
            {
                msMove.MoveTo(msDestination);
                ourMove.MoveTo(ourDestination, null);
            }

            using var msCopy = passNullToMicrosoft
                ? msCopySource.CopyTo(msDestination, null)
                : msCopySource.CopyTo(msDestination);
            using var ourCopy = passNullToMicrosoft
                ? ourCopySource.CopyTo(ourDestination)
                : ourCopySource.CopyTo(ourDestination, null);

            new Comparison($"DirectoryEntry null MoveTo/CopyTo (Microsoft null={passNullToMicrosoft})")
                .Check("moved Name", msMove.Name, ourMove.Name)
                .Check("copied Name", msCopy.Name, ourCopy.Name)
                .Check("moved SchemaClassName", msMove.SchemaClassName, ourMove.SchemaClassName)
                .Check("copied SchemaClassName", msCopy.SchemaClassName, ourCopy.SchemaClassName)
                .Check("Microsoft moved destination", true,
                    msMove.Path.EndsWith($"OU=move-child,{msDestinationDn}", StringComparison.OrdinalIgnoreCase))
                .Check("AdForLinux moved destination", true,
                    ourMove.Path.EndsWith($"OU=move-child,{ourDestinationDn}", StringComparison.OrdinalIgnoreCase))
                .Check("Microsoft copied destination", true,
                    msCopy.Path.EndsWith($"OU=copy-child,{msDestinationDn}", StringComparison.OrdinalIgnoreCase))
                .Check("AdForLinux copied destination", true,
                    ourCopy.Path.EndsWith($"OU=copy-child,{ourDestinationDn}", StringComparison.OrdinalIgnoreCase))
                .Assert();
        }
        finally
        {
            try
            {
                using var root = MicrosoftEntry(rootDn);
                root.DeleteTree();
            }
            catch
            {
                // Best-effort cleanup if setup or either implementation failed.
            }
        }
    }

    private static Ms.DirectoryEntry MicrosoftEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

    private static void CreateOu(Ms.DirectoryEntry parent, string relativeName)
    {
        using var child = parent.Children.Add(relativeName, "organizationalUnit");
        child.CommitChanges();
    }

    private static string Show(string? value) => value is null ? "null" : $"'{value}'";
}
