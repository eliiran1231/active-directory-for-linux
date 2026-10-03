using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// PrincipalContext initialization may bind. Run only in the verified disposable
// AD lab. Computers remain unsaved: no Save, search, or directory write occurs.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityRetainedPrincipalValuesAfterDisposeComparisonTests
{
    // Microsoft ComputerPrincipal exposes an independent tracked value collection.
    // Its mutation methods do not consult the owning principal's lifetime.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Computer.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs
    [Theory]
    [InlineData("Add", false)]
    [InlineData("Add", true)]
    [InlineData("RemoveAt", false)]
    [InlineData("RemoveAt", true)]
    [InlineData("Clear", false)]
    [InlineData("Clear", true)]
    public void Retained_service_names_mutation_after_owner_disposal_matches_microsoft(
        string operation, bool disposeOwner)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);
        using var expectedOwner = new Ms.ComputerPrincipal(expectedContext);
        using var actualOwner = new Ours.ComputerPrincipal(actualContext);
        var expected = expectedOwner.ServicePrincipalNames;
        var actual = actualOwner.ServicePrincipalNames;
        const string seed = "HOST/compat-retained-seed";
        const string added = "HOST/compat-retained-added";
        expected.Add(seed);
        actual.Add(seed);
        Assert.Equal(new[] { seed }, expected.ToArray());
        Assert.Equal(new[] { seed }, actual.ToArray());
        Assert.Same(expected, expectedOwner.ServicePrincipalNames);
        Assert.Same(actual, actualOwner.ServicePrincipalNames);

        if (disposeOwner)
        {
            expectedOwner.Dispose();
            actualOwner.Dispose();
        }

        // Retained reads establish a healthy local collection independently of
        // the later mutation. Do not reacquire it through a disposed owner.
        Assert.Equal(new[] { seed }, expected.ToArray());
        Assert.Equal(new[] { seed }, actual.ToArray());
        // Exercise Contains itself; Assert.Contains would enumerate instead.
        var contains = (expected.Contains(seed), actual.Contains(seed),
            expected.Contains(added), actual.Contains(added));
        Assert.Equal((true, true, false, false), contains);

        var expectedError = Record.Exception(() => Mutate(expected, operation, added));
        var actualError = Record.Exception(() => Mutate(actual, operation, added));
        var expectedValues = expected.ToArray();
        var actualValues = actual.ToArray();

        // Strong Microsoft oracle prerequisite, also checked in each live-owner
        // control. Capture clone contents even if its callback throws after mutation.
        Assert.Null(expectedError);
        Assert.Equal(operation == "Add" ? new[] { seed, added } : Array.Empty<string>(),
            expectedValues);
        new Comparison($"Retained ServicePrincipalNames: {operation}, disposeOwner={disposeOwner}")
            .Check("mutation exception", expectedError?.GetType().FullName, actualError?.GetType().FullName)
            .Check("mutation exception parameter", (expectedError as ArgumentException)?.ParamName,
                (actualError as ArgumentException)?.ParamName)
            .Check("local count after mutation", expected.Count, actual.Count)
            .Check("local contents after mutation", string.Join("|", expectedValues), string.Join("|", actualValues))
            .Check("contains seed after mutation", expected.Contains(seed), actual.Contains(seed))
            .Check("contains added after mutation", expected.Contains(added), actual.Contains(added))
            .Assert();
    }

    private static void Mutate(IList<string> values, string operation, string added)
    {
        switch (operation)
        {
            case "Add": values.Add(added); break;
            case "RemoveAt": values.RemoveAt(0); break;
            case "Clear": values.Clear(); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }
}
