using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class AdvancedFiltersOwnerComparisonTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)] // Normal owner control; no context or AD required.
    public void Protected_constructor_accepts_the_same_owner_values(bool nullOwner)
    {
        using var expectedOwner = new MicrosoftPrincipal();
        using var actualOwner = new OurPrincipal();
        var expectedError = Record.Exception(() =>
            _ = new MicrosoftFilters(nullOwner ? null : expectedOwner));
        var actualError = Record.Exception(() =>
            _ = new OurFilters(nullOwner ? null : actualOwner));

        new Comparison($"AdvancedFilters constructor; null owner={nullOwner}")
            .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
            .Check("parameter", (expectedError as ArgumentException)?.ParamName,
                (actualError as ArgumentException)?.ParamName)
            .Assert();
    }

    // Normal protected subclass APIs, with no reflection or fabricated state.
    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }
    private sealed class MicrosoftFilters(Ms.Principal? owner) : Ms.AdvancedFilters(owner!);
    private sealed class OurFilters(Ours.Principal? owner) : Ours.AdvancedFilters(owner!);
}
