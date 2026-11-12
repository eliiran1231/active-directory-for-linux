using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DirectoryEntryCredentialCacheComparisonTests
{
    [Theory]
    [InlineData("Username", "replacement")]
    [InlineData("Username", "")]
    [InlineData("Username", null)]
    [InlineData("Username", "original")]
    [InlineData("Password", "replacement")]
    [InlineData("Password", "")]
    [InlineData("Password", null)]
    [InlineData("Password", "original")]
    public void Credential_assignment_invalidates_property_wrapper_like_microsoft(
        string property, string? replacement)
    {
        // Reading the wrapper does not bind or fetch attributes. Credentials
        // here are arbitrary local state, not credentials for a real server.
        using var microsoft = new Ms.DirectoryEntry(
            "LDAP://unused.example.test/DC=example,DC=test", "original", "original");
        using var ours = new Ours.DirectoryEntry(
            "LDAP://unused.example.test/DC=example,DC=test", "original", "original");
        var expectedBefore = microsoft.Properties;
        var actualBefore = ours.Properties;

        if (property == "Username")
        {
            microsoft.Username = replacement;
            ours.Username = replacement;
        }
        else
        {
            microsoft.Password = replacement;
            ours.Password = replacement;
        }

        new Comparison($"{property} assignment to {replacement ?? "<null>"}")
            .Check("Username", microsoft.Username, ours.Username)
            .Check("Path", microsoft.Path, ours.Path)
            .Check("preserved property wrapper", ReferenceEquals(expectedBefore, microsoft.Properties),
                ReferenceEquals(actualBefore, ours.Properties))
            .Check("replacement wrapper is cached", ReferenceEquals(microsoft.Properties, microsoft.Properties),
                ReferenceEquals(ours.Properties, ours.Properties))
            .Assert();
    }

    [Theory]
    [InlineData((int)Ms.AuthenticationTypes.None)]
    [InlineData((int)Ms.AuthenticationTypes.Anonymous)]
    [InlineData((int)(Ms.AuthenticationTypes.Secure | Ms.AuthenticationTypes.Signing))]
    [InlineData((int)Ms.AuthenticationTypes.Secure)]
    public void Authentication_assignment_invalidates_property_wrapper_like_microsoft(int replacement)
    {
        using var microsoft = new Ms.DirectoryEntry();
        using var ours = new Ours.DirectoryEntry();
        var expectedBefore = microsoft.Properties;
        var actualBefore = ours.Properties;

        microsoft.AuthenticationType = (Ms.AuthenticationTypes)replacement;
        ours.AuthenticationType = (Ours.AuthenticationTypes)replacement;

        new Comparison($"AuthenticationType assignment to {replacement}")
            .Check("AuthenticationType", (int)microsoft.AuthenticationType, (int)ours.AuthenticationType)
            .Check("preserved property wrapper", ReferenceEquals(expectedBefore, microsoft.Properties),
                ReferenceEquals(actualBefore, ours.Properties))
            .Assert();
    }
}
