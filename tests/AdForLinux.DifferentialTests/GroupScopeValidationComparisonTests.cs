using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class GroupScopeValidationComparisonTests
{
    [Fact]
    public void Group_scope_defines_the_same_named_values_as_microsoft()
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

        // Named enum values do not constrain assignments. Undefined-value
        // setter behavior is compared against Microsoft in
        // NextBatchPrincipalStateComparisonTests.
    }
}
