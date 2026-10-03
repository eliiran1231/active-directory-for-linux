using Xunit;

namespace AdForLinux.DifferentialTests;

public class DifferentialSettingsTests
{
    [Theory]
    [InlineData("OU=run,OU=CI,DC=lab,DC=test", true)]
    [InlineData("ou=RUN,ou=ci,dc=LAB,dc=TEST", true)]
    [InlineData("OU=children,OU=run,OU=CI,DC=lab,DC=test", true)]
    [InlineData(@"CN=child\,name,OU=run,OU=CI,DC=lab,DC=test", true)]
    [InlineData(@"CN=other\,OU=run,OU=CI,DC=lab,DC=test", false)]
    [InlineData("OU=CI,DC=lab,DC=test", false)]
    [InlineData("OU=another-run,OU=CI,DC=lab,DC=test", false)]
    public void Override_must_have_the_disposable_ou_as_an_actual_ancestor(string container, bool expected)
        => Assert.Equal(expected,
            DifferentialSettings.IsWithinTestBase(container, "OU=run,OU=CI,DC=lab,DC=test"));
}
