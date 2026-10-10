using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class SecurityRuleValidationComparisonTests
{
    [Theory]
    [InlineData(-1, false)]
    [InlineData(5, false)]
    [InlineData(-1, true)]
    [InlineData(5, true)]
    public void Invalid_inheritance_reports_the_same_constructor_parameter(int inheritance, bool audit)
    {
        // Use a well-known SID so construction needs no account lookup or AD.
        var identity = new SecurityIdentifier("S-1-1-0");
        var expected = Record.Exception(() =>
        {
            if (audit)
                _ = new Ms.ActiveDirectoryAuditRule(identity, Ms.ActiveDirectoryRights.ReadProperty,
                    AuditFlags.Success, (Ms.ActiveDirectorySecurityInheritance)inheritance);
            else
                _ = new Ms.ActiveDirectoryAccessRule(identity, Ms.ActiveDirectoryRights.ReadProperty,
                    AccessControlType.Allow, (Ms.ActiveDirectorySecurityInheritance)inheritance);
        });
        var actual = Record.Exception(() =>
        {
            if (audit)
                _ = new Ours.ActiveDirectoryAuditRule(new AdForLinux.Security.Principal.SecurityIdentifier(identity.Value), Ours.ActiveDirectoryRights.ReadProperty,
                    AuditFlags.Success, (Ours.ActiveDirectorySecurityInheritance)inheritance);
            else
                _ = new Ours.ActiveDirectoryAccessRule(new AdForLinux.Security.Principal.SecurityIdentifier(identity.Value), Ours.ActiveDirectoryRights.ReadProperty,
                    AccessControlType.Allow, (Ours.ActiveDirectorySecurityInheritance)inheritance);
        });

        var expectedArgument = Assert.IsType<InvalidEnumArgumentException>(expected);
        var actualArgument = Assert.IsType<InvalidEnumArgumentException>(actual);
        Assert.Equal("inheritanceType", expectedArgument.ParamName);
        Assert.Equal(expectedArgument.ParamName, actualArgument.ParamName);
    }
}
