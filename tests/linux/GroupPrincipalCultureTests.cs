using System.Globalization;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public sealed class GroupPrincipalCultureTests
{
    [Theory]
    [InlineData("", "fa-IR")]
    [InlineData("fa-IR", "")]
    [InlineData("", "ar-SA")]
    [InlineData("ar-SA", "")]
    public void Unsaved_group_flags_survive_culture_changes(string writer, string reader)
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            using var context = new PrincipalContext(ContextType.Domain,
                "unused.example.test", "DC=example,DC=test",
                ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer, null, null);
            using var group = new GroupPrincipal(context);
            Assert.Null(group.IsSecurityGroup);
            Assert.Null(group.GroupScope);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(writer);
            group.GroupScope = GroupScope.Global;
            group.IsSecurityGroup = true;
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(reader);
            Assert.Equal(true, group.IsSecurityGroup);
            Assert.Equal(GroupScope.Global, group.GroupScope);
            group.GroupScope = GroupScope.Universal;
            Assert.Equal(true, group.IsSecurityGroup);
            Assert.Equal(GroupScope.Universal, group.GroupScope);
            Assert.Null(group.Guid);
            Assert.Null(group.DistinguishedName);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }
}
