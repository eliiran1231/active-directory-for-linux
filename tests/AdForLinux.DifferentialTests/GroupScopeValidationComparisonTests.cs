using System.ComponentModel;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class GroupScopeValidationComparisonTests
{
    [Fact]
    public void Group_scope_accepts_only_values_defined_by_microsoft()
    {
        Assert.Equal(
            Enum.GetValues<Ms.GroupScope>().Select(value => (int)value),
            Enum.GetValues<Ours.GroupScope>().Select(value => (int)value));

        using var context = new Ours.PrincipalContext(
            Ours.ContextType.Domain,
            "offline.example.test",
            "DC=example,DC=test");
        using var group = new Ours.GroupPrincipal(context);

        foreach (var scope in Enum.GetValues<Ours.GroupScope>())
        {
            group.GroupScope = scope;
            Assert.Equal(scope, group.GroupScope);
        }

        var exception = Assert.Throws<InvalidEnumArgumentException>(
            () => group.GroupScope = (Ours.GroupScope)int.MaxValue);
        Assert.Equal("value", exception.ParamName);
        Assert.Equal(Ours.GroupScope.Universal, group.GroupScope);
    }
}
