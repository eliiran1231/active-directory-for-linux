using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// A supported protected Principal constructor permits an extension object to
// exist before ContextRaw is assigned. No PrincipalContext is constructed here,
// so these operations cannot discover or connect to a directory.
// Pinned reference: dotnet/runtime v9.0.0, PrincipalSearcher.cs: the constructor
// initializes paging through its context; the QueryFilter setter only stores it.
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
    public void Searcher_with_contextless_assigned_filter_matches_microsoft(string member, bool dispose)
    {
        using var expectedFilter = new MicrosoftPrincipal();
        using var actualFilter = new OurPrincipal();
        using var microsoft = new Ms.PrincipalSearcher();
        using var ours = new Ours.PrincipalSearcher();
        // Do not use PrincipalSearcher(filter): constructor initialization is a
        // separate contract above. Assignment reaches these operations without
        // eagerly initializing a native searcher in Microsoft.
        microsoft.QueryFilter = expectedFilter;
        ours.QueryFilter = actualFilter;
        Assert.Same(expectedFilter, microsoft.QueryFilter);
        Assert.Same(actualFilter, ours.QueryFilter);
        Assert.Null(microsoft.Context);
        Assert.Null(ours.Context);
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
        Assert.Equal((Describe(expectedError), expectedType), (Describe(actualError), actualType));
    }

    private static (Type? Type, string? Parameter) Describe(Exception? error) =>
        (error?.GetType(), (error as ArgumentException)?.ParamName);
}
