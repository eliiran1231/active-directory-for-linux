using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Property setters validate against the context, so AD_* configuration is
// required. Principals remain unsaved; these tests never write to the server.
[Collection("differential")]
public sealed class PrincipalExtensionPropertyIsolationComparisonTests
{
    [Theory]
    [InlineData("Description", "description", "staged")]
    [InlineData("Description", "description", null)]
    [InlineData("DisplayName", "displayName", "staged")]
    [InlineData("SamAccountName", "sAMAccountName", "staged")]
    [InlineData("UserPrincipalName", "userPrincipalName", "staged@example.test")]
    [InlineData("GivenName", "givenName", "staged")]
    [InlineData("Description", "unrelatedAttribute", "staged")] // Control.
    public void Unsaved_standard_property_does_not_populate_extension_cache(
        string property, string attribute, string? value)
    {
        using var microsoftContext = new Ms.PrincipalContext(
            Ms.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(
            Ours.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var microsoft = new MicrosoftUser(microsoftContext);
        using var ours = new OurUser(ourContext);
        var expectedProperty = typeof(Ms.UserPrincipal).GetProperty(property)!;
        var actualProperty = typeof(Ours.UserPrincipal).GetProperty(property)!;
        Assert.Empty(microsoft.Read(attribute));
        Assert.Empty(ours.Read(attribute));

        // Reflection only selects public properties; setup failures are not
        // swallowed or confused with the extension-cache observation.
        expectedProperty.SetValue(microsoft, value);
        actualProperty.SetValue(ours, value);
        Assert.Equal(value, expectedProperty.GetValue(microsoft));
        Assert.Equal(value, actualProperty.GetValue(ours));
        var expectedAfterStandardSet = microsoft.Read(attribute);
        var actualAfterStandardSet = ours.Read(attribute);

        // Control: explicit extension writes remain independent of the ordinary
        // property's staged value and do become visible to ExtensionGet.
        microsoft.Write(attribute, "extension");
        ours.Write(attribute, "extension");
        Assert.Equal(new object?[] { "extension" }, microsoft.Read(attribute));
        Assert.Equal(microsoft.Read(attribute), ours.Read(attribute));
        Assert.Equal(value, expectedProperty.GetValue(microsoft));
        Assert.Equal(value, actualProperty.GetValue(ours));
        Assert.Equal(expectedAfterStandardSet, actualAfterStandardSet);
    }

    private sealed class MicrosoftUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        public object[] Read(string attribute) => ExtensionGet(attribute);
        public void Write(string attribute, object value) => ExtensionSet(attribute, value);
    }

    private sealed class OurUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        public object?[] Read(string attribute) => ExtensionGet(attribute);
        public void Write(string attribute, object value) => ExtensionSet(attribute, value);
    }
}
