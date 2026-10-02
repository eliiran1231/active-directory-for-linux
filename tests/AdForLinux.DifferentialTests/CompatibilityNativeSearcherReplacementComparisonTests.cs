using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Context/native-searcher initialization can bind. This only renders filters;
// there is no Find/Save call. Run solely in the verified disposable AD lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityNativeSearcherReplacementComparisonTests
{
    // Microsoft QueryFilter updates Context without clearing UnderlyingSearcher.
    // PushFilterToNativeSearcher only constructs a native searcher if it is null.
    // Existing replacement tests never materialize that searcher first, so they
    // cannot observe whether a replacement loses caller configuration.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Replacing_filter_retains_native_searcher_configuration_like_microsoft(bool distinctContext)
    {
        using var expectedFirstContext = MicrosoftContext();
        using var expectedSecondContext = MicrosoftContext();
        using var actualFirstContext = OurContext();
        using var actualSecondContext = OurContext();
        using var expectedFilter = new Ms.UserPrincipal(expectedFirstContext) { SamAccountName = "native-first" };
        using var actualFilter = new Ours.UserPrincipal(actualFirstContext) { SamAccountName = "native-first" };
        var expectedReplacementContext = distinctContext ? expectedSecondContext : expectedFirstContext;
        var actualReplacementContext = distinctContext ? actualSecondContext : actualFirstContext;
        using var expectedReplacement = new Ms.UserPrincipal(expectedReplacementContext) { SamAccountName = "native-replacement" };
        using var actualReplacement = new Ours.UserPrincipal(actualReplacementContext) { SamAccountName = "native-replacement" };
        using var microsoft = new Ms.PrincipalSearcher(expectedFilter);
        using var ours = new Ours.PrincipalSearcher(actualFilter);
        var expectedNative = Assert.IsType<MsDirectory.DirectorySearcher>(microsoft.GetUnderlyingSearcher());
        var actualNative = Assert.IsType<OurDirectory.DirectorySearcher>(ours.GetUnderlyingSearcher());
        var expectedInitialFilter = expectedNative.Filter;
        Assert.Contains("native-first", expectedInitialFilter);
        expectedNative.PageSize = actualNative.PageSize = 17;
        expectedNative.SizeLimit = actualNative.SizeLimit = 3;
        Assert.Equal(17, expectedNative.PageSize);
        Assert.Equal(3, expectedNative.SizeLimit);
        var comparison = new Comparison($"Native searcher after QueryFilter replacement: distinctContext={distinctContext}");
        comparison.Check("initial filter", expectedInitialFilter, actualNative.Filter);

        // Both context instances address exactly the same endpoint/container;
        // this tests object ownership/configuration, not cross-domain routing.
        microsoft.QueryFilter = expectedReplacement;
        ours.QueryFilter = actualReplacement;
        Assert.Same(expectedReplacement, microsoft.QueryFilter);
        Assert.Same(expectedReplacementContext, microsoft.Context);
        comparison.Check("replacement filter identity", ReferenceEquals(expectedReplacement, microsoft.QueryFilter),
                ReferenceEquals(actualReplacement, ours.QueryFilter))
            .Check("replacement context identity", ReferenceEquals(expectedReplacementContext, microsoft.Context),
                ReferenceEquals(actualReplacementContext, ours.Context));
        var expectedAfter = Assert.IsType<MsDirectory.DirectorySearcher>(microsoft.GetUnderlyingSearcher());
        var actualAfter = Assert.IsType<OurDirectory.DirectorySearcher>(ours.GetUnderlyingSearcher());
        Assert.Contains("native-replacement", expectedAfter.Filter);
        Assert.NotEqual(expectedInitialFilter, expectedAfter.Filter);
        comparison.Check("retains native object", ReferenceEquals(expectedNative, expectedAfter), ReferenceEquals(actualNative, actualAfter))
            .Check("PageSize after replacement", expectedAfter.PageSize, actualAfter.PageSize)
            .Check("SizeLimit after replacement", expectedAfter.SizeLimit, actualAfter.SizeLimit)
            .Check("updated filter", expectedAfter.Filter, actualAfter.Filter)
            .Check("repeated native getter identity", ReferenceEquals(expectedAfter, microsoft.GetUnderlyingSearcher()),
                ReferenceEquals(actualAfter, ours.GetUnderlyingSearcher()))
            .Assert();
    }

    private static Ms.PrincipalContext MicrosoftContext() => new(Ms.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() => new(Ours.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
}
