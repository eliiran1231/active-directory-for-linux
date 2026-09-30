using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class NativeGuidRepresentationComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData("user")]
    [InlineData("group")]
    [InlineData("computer")]
    public void NativeGuid_preserves_the_ldap_provider_representation(string objectClass)
    {
        var dn = objectClass switch
        {
            "user" => data.UserDn,
            "group" => data.GroupDn,
            "computer" => data.ComputerDn,
            _ => throw new ArgumentOutOfRangeException(nameof(objectClass)),
        };
        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(dn), DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);

        // Establish that both reads refer to the same nonempty object identity.
        // NativeGuid is a provider string, so parsing/normalizing it would hide
        // formatting and byte-order differences that callers can observe.
        Assert.NotEqual(Guid.Empty, microsoft.Guid);
        Assert.Equal(microsoft.Guid, ours.Guid);
        Assert.Equal(microsoft.NativeGuid, ours.NativeGuid);
    }
}
