using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Context initialization and Name can bind. Run only in the verified disposable
// AD lab. These cases perform reads only, with no Find, Save, or CommitChanges.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityRetainedSearchRootComparisonTests
{
    // ADStoreCtx supplies its context entry to the native DirectorySearcher.
    // Microsoft DirectorySearcher.Dispose only disposes an internally allocated
    // root, so disposing the PAPI searcher must leave that borrowed entry alive
    // while its owning context remains alive. Retain the entry itself: reading
    // the disposed PAPI searcher's members tests a different lifetime contract.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs
    // Conversely, PrincipalContext owns its ADStoreCtx (ownCtxBase=true), whose
    // Dispose releases ctxBase. Retaining the native searcher does not transfer
    // ownership away from that context.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Context.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    [Theory]
    [InlineData("Neither")]
    [InlineData("Searcher")]
    [InlineData("Context")]
    public void Retained_native_root_lifetime_matches_microsoft(string disposeOwner)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expectedFilter = new Ms.UserPrincipal(expectedContext);
        using var actualFilter = new Ours.UserPrincipal(actualContext);
        using var microsoft = new Ms.PrincipalSearcher(expectedFilter);
        using var ours = new Ours.PrincipalSearcher(actualFilter);
        var expectedNative = Assert.IsType<MsDirectory.DirectorySearcher>(microsoft.GetUnderlyingSearcher());
        var actualNative = Assert.IsType<OurDirectory.DirectorySearcher>(ours.GetUnderlyingSearcher());
        var expectedRoot = Assert.IsType<MsDirectory.DirectoryEntry>(expectedNative.SearchRoot);
        var actualRoot = Assert.IsType<OurDirectory.DirectoryEntry>(actualNative.SearchRoot);

        // Successful reads on both sides rule out an unavailable root or failed
        // initial bind as the explanation for a later lifetime difference.
        var expectedBefore = expectedRoot.Name;
        var actualBefore = actualRoot.Name;
        Assert.False(string.IsNullOrEmpty(expectedBefore));
        Assert.False(string.IsNullOrEmpty(actualBefore));
        var comparison = new Comparison($"Retained native root: disposeOwner={disposeOwner}")
            .Check("Name before disposal", expectedBefore, actualBefore);

        if (disposeOwner == "Searcher")
        {
            microsoft.Dispose();
            ours.Dispose();
        }
        else if (disposeOwner == "Context")
        {
            expectedContext.Dispose();
            actualContext.Dispose();
        }

        string? expectedAfter = null;
        string? actualAfter = null;
        var expectedError = Record.Exception(() => { expectedAfter = expectedRoot.Name; });
        var actualError = Record.Exception(() => { actualAfter = actualRoot.Name; });
        if (disposeOwner == "Context")
        {
            Assert.IsType<ObjectDisposedException>(expectedError);
        }
        else
        {
            Assert.Null(expectedError);
            Assert.Equal(expectedBefore, expectedAfter);
        }
        comparison.Check("Name read exception", expectedError?.GetType().Name, actualError?.GetType().Name)
            .Check("disposed object name", (expectedError as ObjectDisposedException)?.ObjectName,
                (actualError as ObjectDisposedException)?.ObjectName)
            .Check("Name after disposal or control", expectedAfter, actualAfter)
            .Assert();

        // Do not dispose the borrowed roots independently. Scope exit also
        // disposes each searcher/context not explicitly disposed in this row.
    }
}
