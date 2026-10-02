using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Read-only LDAP operations against a proven missing child DN. Run exclusively
// in the verified disposable lab; these cases create/delete no directory objects.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityNativeFailureStateComparisonTests
{
    // ADStoreCtx.Query temporarily sets SizeLimit for FindOne, but restores it
    // only after native FindAll and ADEntriesSet construction succeed. FindAll
    // passes -1, leaving the caller limit unchanged. Inspect the retained native
    // instance immediately after failure, without another preparation accessor.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Failed_search_preserves_native_limit_like_microsoft(bool findAll)
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
        var expectedName = expectedRoot.Name;
        var actualName = actualRoot.Name;
        Assert.False(string.IsNullOrEmpty(expectedName));
        Assert.False(string.IsNullOrEmpty(actualName));

        var missingDn = $"CN=compat-missing-{Guid.NewGuid():N},{DifferentialSettings.UsersContainer}";
        using var expectedMissing = new MsDirectory.DirectoryEntry(DifferentialSettings.PathFor(missingDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actualMissing = new OurDirectory.DirectoryEntry(DifferentialSettings.PathFor(missingDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        var absenceError = Assert.IsAssignableFrom<COMException>(Record.Exception(() => expectedMissing.RefreshCache()));
        Assert.Equal(unchecked((int)0x80072030), absenceError.ErrorCode);

        expectedNative.SizeLimit = actualNative.SizeLimit = 7;
        Assert.Equal(7, expectedNative.SizeLimit);
        Assert.Equal(7, actualNative.SizeLimit);
        var comparison = new Comparison($"Failed native search state: findAll={findAll}")
            .Check("initial root Name", expectedName, actualName);
        try
        {
            expectedNative.SearchRoot = expectedMissing;
            actualNative.SearchRoot = actualMissing;
            var expectedError = Record.Exception(() =>
            {
                if (findAll)
                {
                    using var results = microsoft.FindAll();
                }
                else
                {
                    using var result = microsoft.FindOne();
                }
            });
            var actualError = Record.Exception(() =>
            {
                if (findAll)
                {
                    using var results = ours.FindAll();
                }
                else
                {
                    using var result = ours.FindOne();
                }
            });
            var expectedMissingError = Assert.IsType<Ms.PrincipalOperationException>(expectedError);
            Assert.Equal(absenceError.ErrorCode, expectedMissingError.ErrorCode);
            comparison.Check("failure type", expectedMissingError.GetType().Name, actualError?.GetType().Name)
                .Check("failure code", (expectedError as Ms.PrincipalOperationException)?.ErrorCode,
                    (actualError as Ours.PrincipalOperationException)?.ErrorCode)
                .Check("SizeLimit immediately after failure", expectedNative.SizeLimit, actualNative.SizeLimit)
                .Check("retained caller root", ReferenceEquals(expectedMissing, expectedNative.SearchRoot),
                    ReferenceEquals(actualMissing, actualNative.SearchRoot))
                .Assert();
        }
        finally
        {
            // Restore borrowed roots before the separately owned missing-entry
            // wrappers are disposed. No recovery search on the broad root.
            expectedNative.SearchRoot = expectedRoot;
            actualNative.SearchRoot = actualRoot;
        }
    }
}
