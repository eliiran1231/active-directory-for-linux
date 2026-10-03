using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class PrincipalContextNameComparisonTests
{
    [Fact]
    public void Name_preserves_the_explicit_server_port_like_microsoft()
    {
        // Use the configured endpoint, including its port even when it is the
        // default. Microsoft verifies the server during construction, so this
        // needs AD but does not create or modify any directory objects.
        var name = $"{DifferentialSettings.Host}:{DifferentialSettings.Port}";
        using var expected = new Ms.PrincipalContext(Ms.ContextType.Domain, name,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actual = new Ours.PrincipalContext(Ours.ContextType.Domain, name,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

        Assert.Equal(name, expected.Name);
        new Comparison("PrincipalContext constructed with an explicit port")
            .Check("Name", expected.Name, actual.Name)
            .Check("Container control", expected.Container, actual.Container)
            .Check("UserName control", expected.UserName, actual.UserName)
            .Check("Options control", (int)expected.Options, (int)actual.Options)
            .Assert();
    }
}
