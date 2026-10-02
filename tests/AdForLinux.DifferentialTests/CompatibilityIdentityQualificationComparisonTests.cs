using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// TestDataFixture creates and deletes accounts: use only the disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityIdentityQualificationComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    // IdentityClaimToFilter's SamAccountScheme strips the FIRST backslash
    // prefix and treats a trailing separator as malformed. Value-only lookup
    // uses a separate path, so its existing normalization does not prove that
    // explicit IdentityType.SamAccountName has equivalent behavior.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    // Source blob: a6f44f8f185ddfcf025a93e654316b981a329e6c
    [Theory]
    [InlineData("bare")]
    [InlineData("qualified")]
    [InlineData("empty-qualifier")]
    [InlineData("trailing-separator")]
    [InlineData("repeated-separator")]
    public void Explicit_sam_identity_qualification_matches_microsoft(string form)
    {
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        // Every row, including malformed forms, must first prove that both
        // contexts can find the fixture. Matching environmental errors below
        // must not stand in for an identity-qualification comparison.
        using (var expectedControl = Ms.UserPrincipal.FindByIdentity(
            microsoftContext, Ms.IdentityType.SamAccountName, data.UserName))
        using (var actualControl = Ours.UserPrincipal.FindByIdentity(
            ourContext, Ours.IdentityType.SamAccountName, data.UserName))
        {
            Assert.NotNull(expectedControl);
            Assert.NotNull(actualControl);
            Assert.Equal(data.UserDn.ToUpperInvariant(), expectedControl.DistinguishedName?.ToUpperInvariant());
            Assert.Equal(data.UserDn.ToUpperInvariant(), actualControl.DistinguishedName?.ToUpperInvariant());
        }
        var identity = form switch
        {
            "bare" => data.UserName,
            // The source treats this as a syntactic qualifier. A synthetic value
            // makes the test independent of the lab's actual NetBIOS domain.
            "qualified" => $"ADFL-IGNORED\\{data.UserName}",
            "empty-qualifier" => $"\\{data.UserName}",
            "trailing-separator" => $"{data.UserName}\\",
            "repeated-separator" => $"ADFL-IGNORED\\SECOND\\{data.UserName}",
            _ => throw new ArgumentOutOfRangeException(nameof(form)),
        };
        var comparison = new Comparison($"FindByIdentity SamAccountName qualification: {form}");
        var expected = ObserveMicrosoft(() => Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, identity));
        var actual = ObserveOurs(() => Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.SamAccountName, identity));
        if (form is "bare" or "qualified" or "empty-qualifier")
        {
            Assert.Null(expected.Error);
            Assert.Equal(data.UserDn.ToUpperInvariant(), expected.Dn);
        }
        Compare(comparison, "explicit SamAccountName", expected, actual);

        // Compare the two overloads independently to the oracle: malformed
        // explicit input may throw while inference simply skips that scheme.
        expected = ObserveMicrosoft(() => Ms.UserPrincipal.FindByIdentity(microsoftContext, identity));
        actual = ObserveOurs(() => Ours.UserPrincipal.FindByIdentity(ourContext, identity));
        Compare(comparison, "value-only control", expected, actual);
        comparison.Assert();
    }

    private static (string? Error, string? Parameter, string? Dn) ObserveMicrosoft(Func<Ms.UserPrincipal?> find)
    {
        try
        {
            using var principal = find();
            return (null, null, principal?.DistinguishedName?.ToUpperInvariant());
        }
        catch (Exception error)
        {
            return (error.GetType().Name, (error as ArgumentException)?.ParamName, null);
        }
    }

    private static (string? Error, string? Parameter, string? Dn) ObserveOurs(Func<Ours.UserPrincipal?> find)
    {
        try
        {
            using var principal = find();
            return (null, null, principal?.DistinguishedName?.ToUpperInvariant());
        }
        catch (Exception error)
        {
            return (error.GetType().Name, (error as ArgumentException)?.ParamName, null);
        }
    }

    private static void Compare(Comparison comparison, string label,
        (string? Error, string? Parameter, string? Dn) expected,
        (string? Error, string? Parameter, string? Dn) actual)
    {
        comparison.Check($"{label}: exception", expected.Error, actual.Error)
            .Check($"{label}: parameter", expected.Parameter, actual.Parameter)
            .Check($"{label}: distinguished name", expected.Dn, actual.Dn);
    }
}
