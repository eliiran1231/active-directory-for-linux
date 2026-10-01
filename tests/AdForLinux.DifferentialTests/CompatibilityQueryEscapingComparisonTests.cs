using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Translation only: no Find/Save call. PrincipalContext initialization can bind,
// so these cases require Windows and the configured isolated lab, not offline CI.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityQueryEscapingComparisonTests
{
    // PAPI escaping is not RFC4515 literal escaping: backslashes can quote '*',
    // a backslash, parentheses or ordinary characters. Microsoft builds the
    // expected filter here; no separately implemented escaping oracle is used.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs
    [Theory]
    [InlineData("displayName", "team*")]
    [InlineData("displayName", @"team\*")]
    [InlineData("displayName", @"team\\*")]
    [InlineData("displayName", @"team\q")]
    [InlineData("displayName", @"team\")]
    [InlineData("displayName", "(team)")]
    [InlineData("displayName", @"\28team\29")]
    [InlineData("displayName", @"\(team\)")]
    [InlineData("workstations", @"DESK\*")]
    [InlineData("workstations", @"lab\\box")]
    [InlineData("servicePrincipalNames", @"HTTP/host\*")]
    [InlineData("servicePrincipalNames", @"HTTP/host\\name")]
    [InlineData("extension", @"team\*")]
    [InlineData("extension", @"team\\name")]
    public void Papi_quoted_values_and_subsequent_replacement_match_microsoft(string property, string pattern)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using Ms.Principal expected = property switch
        {
            "servicePrincipalNames" => new Ms.ComputerPrincipal(expectedContext),
            "extension" => new MicrosoftExtensionUser(expectedContext),
            _ => new Ms.UserPrincipal(expectedContext),
        };
        using Ours.Principal actual = property switch
        {
            "servicePrincipalNames" => new Ours.ComputerPrincipal(actualContext),
            "extension" => new OurExtensionUser(actualContext),
            _ => new Ours.UserPrincipal(actualContext),
        };
        using var expectedSearcher = new Ms.PrincipalSearcher(expected);
        using var actualSearcher = new Ours.PrincipalSearcher(actual);
        var comparison = new Comparison($"QBE {property}: {pattern}");
        Step("quoted input", pattern);
        Step("replacement control", "plain-recovery");
        comparison.Assert();

        void Step(string label, string value)
        {
            var expectedSetError = Record.Exception(() => Set(expected, property, value));
            var actualSetError = Record.Exception(() => Set(actual, property, value));
            CompareError(comparison, $"{label} setter", expectedSetError, actualSetError);
            string? expectedLdap = null;
            string? actualLdap = null;
            var expectedBuildError = Record.Exception(() => expectedLdap =
                Assert.IsType<System.DirectoryServices.DirectorySearcher>(expectedSearcher.GetUnderlyingSearcher()).Filter);
            var actualBuildError = Record.Exception(() => actualLdap =
                Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(actualSearcher.GetUnderlyingSearcher()).Filter);
            CompareError(comparison, $"{label} translation", expectedBuildError, actualBuildError);
            comparison.Check($"{label} LDAP filter", expectedLdap, actualLdap);
            // The ordinary replacement is a positive translation control and
            // prevents matched environmental exceptions from passing silently.
            if (label == "replacement control")
            {
                Assert.Null(expectedSetError);
                Assert.Null(expectedBuildError);
                Assert.Contains("plain-recovery", expectedLdap);
            }
        }
    }

    private static void Set(Ms.Principal principal, string property, string value)
    {
        switch (property)
        {
            case "displayName": principal.DisplayName = value; break;
            case "workstations":
                var workstations = ((Ms.UserPrincipal)principal).PermittedWorkstations;
                workstations.Clear(); workstations.Add(value); break;
            case "servicePrincipalNames":
                var names = ((Ms.ComputerPrincipal)principal).ServicePrincipalNames;
                names.Clear(); names.Add(value); break;
            case "extension": ((MicrosoftExtensionUser)principal).Write(value); break;
            default: throw new ArgumentOutOfRangeException(nameof(property));
        }
    }

    private static void Set(Ours.Principal principal, string property, string value)
    {
        switch (property)
        {
            case "displayName": principal.DisplayName = value; break;
            case "workstations":
                var workstations = ((Ours.UserPrincipal)principal).PermittedWorkstations;
                workstations.Clear(); workstations.Add(value); break;
            case "servicePrincipalNames":
                var names = ((Ours.ComputerPrincipal)principal).ServicePrincipalNames;
                names.Clear(); names.Add(value); break;
            case "extension": ((OurExtensionUser)principal).Write(value); break;
            default: throw new ArgumentOutOfRangeException(nameof(property));
        }
    }

    private static void CompareError(Comparison comparison, string label, Exception? expected, Exception? actual) => comparison
        .Check($"{label}: exception", expected?.GetType().Name, actual?.GetType().Name)
        .Check($"{label}: parameter", (expected as ArgumentException)?.ParamName, (actual as ArgumentException)?.ParamName);

    [Ms.DirectoryObjectClass("user")]
    private sealed class MicrosoftExtensionUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        public void Write(string value) => ExtensionSet("description", value);
    }

    [Ours.DirectoryObjectClass("user")]
    private sealed class OurExtensionUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        public void Write(string value) => ExtensionSet("description", value);
    }
}
