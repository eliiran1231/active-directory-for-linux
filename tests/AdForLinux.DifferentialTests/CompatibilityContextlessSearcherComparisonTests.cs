using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// A supported protected Principal constructor permits an extension object to
// exist before ContextRaw is assigned. No PrincipalContext is constructed here,
// so these operations cannot discover or connect to a directory.
// Microsoft's empty protected constructor leaves unpersisted=false, so the
// searcher rejects this object as a persisted filter before reading its context.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs
[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilityContextlessSearcherComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }

    [Fact]
    public void Constructor_with_contextless_extension_principal_matches_microsoft()
    {
        using var expectedFilter = new MicrosoftPrincipal();
        using var actualFilter = new OurPrincipal();
        Assert.Null(expectedFilter.Context);
        Assert.Null(actualFilter.Context);
        var expectedError = Record.Exception(() =>
        {
            using var searcher = new Ms.PrincipalSearcher(expectedFilter);
        });
        var actualError = Record.Exception(() =>
        {
            using var searcher = new Ours.PrincipalSearcher(actualFilter);
        });
        Assert.Equal(Describe(expectedError), Describe(actualError));
    }

    [Theory]
    [InlineData("FindOne", false)]
    [InlineData("FindAll", false)]
    [InlineData("GetUnderlyingSearcher", false)]
    [InlineData("GetUnderlyingSearcherType", false)]
    [InlineData("FindOne", true)]
    [InlineData("FindAll", true)]
    [InlineData("GetUnderlyingSearcher", true)]
    [InlineData("GetUnderlyingSearcherType", true)]
    public void Rejected_contextless_filter_assignment_and_followup_match_microsoft(string member, bool dispose)
    {
        using var expectedFilter = new MicrosoftPrincipal();
        using var actualFilter = new OurPrincipal();
        using var microsoft = new Ms.PrincipalSearcher();
        using var ours = new Ours.PrincipalSearcher();
        Assert.Null(microsoft.QueryFilter);
        Assert.Null(ours.QueryFilter);
        // Capture assignment itself: Windows 9.0.0 rejects this principal.
        // Comparing only later operations would mistake a setup failure for
        // evidence about an assigned contextless filter.
        var expectedAssignmentError = Record.Exception(() => microsoft.QueryFilter = expectedFilter);
        var actualAssignmentError = Record.Exception(() => ours.QueryFilter = actualFilter);
        Assert.IsType<ArgumentException>(expectedAssignmentError);
        Assert.Null(microsoft.QueryFilter);
        Assert.Null(microsoft.Context);
        var comparison = new Comparison($"Rejected contextless filter: member={member}, dispose={dispose}")
            .Check("assignment exception", Describe(expectedAssignmentError), Describe(actualAssignmentError))
            .Check("filter remains empty", microsoft.QueryFilter is null, ours.QueryFilter is null)
            .Check("context remains empty", microsoft.Context is null, ours.Context is null);

        // Follow each provider's independently reached state. Microsoft's
        // searcher is still empty; a clone that accepted the filter can have a
        // different state, which is recorded above without aborting this probe.
        if (dispose)
        {
            microsoft.Dispose();
            ours.Dispose();
        }

        string? expectedType = null;
        string? actualType = null;
        var expectedError = Record.Exception(() =>
        {
            switch (member)
            {
                case "FindOne": using (microsoft.FindOne()) { } break;
                case "FindAll": using (microsoft.FindAll()) { } break;
                case "GetUnderlyingSearcher":
                    var expectedNative = microsoft.GetUnderlyingSearcher();
                    expectedType = expectedNative.GetType().Name;
                    break;
                default: expectedType = microsoft.GetUnderlyingSearcherType().Name; break;
            }
        });
        var actualError = Record.Exception(() =>
        {
            switch (member)
            {
                case "FindOne": using (ours.FindOne()) { } break;
                case "FindAll": using (ours.FindAll()) { } break;
                case "GetUnderlyingSearcher":
                    var actualNative = ours.GetUnderlyingSearcher();
                    actualType = actualNative.GetType().Name;
                    break;
                default: actualType = ours.GetUnderlyingSearcherType().Name; break;
            }
        });
        if (dispose) Assert.IsType<ObjectDisposedException>(expectedError);
        else Assert.IsType<InvalidOperationException>(expectedError);
        comparison.Check("follow-up exception", Describe(expectedError), Describe(actualError))
            .Check("follow-up native type", expectedType, actualType)
            .Assert();
    }

    private static (Type? Type, string? Parameter) Describe(Exception? error) =>
        (error?.GetType(), (error as ArgumentException)?.ParamName);
}
