using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Context construction may bind: authorized disposable AD lab only. All users
// are constructed normally and remain unsaved; these probes perform no Save
// or persisted account operation. No private/native state is fabricated.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityUnsavedUnlockComparisonTests
{
    // AccountInfo.UnlockAccount has no action for an unpersisted principal.
    // AuthenticablePrincipal.AccountInfo checks disposal before returning even
    // an already-created helper, so the disposed case is a guard control.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AuthenticablePrincipal.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unlock_unsaved_user_matches_noop_or_disposed_guard(bool dispose)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expected = new Ms.UserPrincipal(expectedContext);
        using var actual = new Ours.UserPrincipal(actualContext);
        Assert.Same(expectedContext, expected.Context);
        Assert.Same(actualContext, actual.Context);
        Assert.Null(expected.DistinguishedName);
        Assert.Null(actual.DistinguishedName);
        Assert.Null(expected.Guid);
        Assert.Null(actual.Guid);
        Assert.False(expected.IsAccountLockedOut());
        Assert.False(actual.IsAccountLockedOut());
        if (dispose)
        {
            expected.Dispose();
            actual.Dispose();
        }

        var comparison = new Comparison($"Unsaved UnlockAccount: disposed={dispose}");
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var expectedError = Record.Exception(expected.UnlockAccount);
            var actualError = Record.Exception(actual.UnlockAccount);
            if (dispose) Assert.IsType<ObjectDisposedException>(expectedError);
            else Assert.Null(expectedError);
            comparison.Check($"attempt {attempt}: exception", expectedError?.GetType().Name, actualError?.GetType().Name)
                .Check($"attempt {attempt}: parameter", (expectedError as ArgumentException)?.ParamName,
                    (actualError as ArgumentException)?.ParamName);
            if (!dispose)
            {
                // A successful no-op leaves the principal unsaved and unlocked;
                // repeating the call must not transition to a persisted path.
                Assert.Null(expected.DistinguishedName);
                Assert.Null(actual.DistinguishedName);
                Assert.Null(expected.Guid);
                Assert.Null(actual.Guid);
                Assert.False(expected.IsAccountLockedOut());
                Assert.False(actual.IsAccountLockedOut());
                Assert.Same(expectedContext, expected.Context);
                Assert.Same(actualContext, actual.Context);
            }
        }
        comparison.Assert();
    }
}
