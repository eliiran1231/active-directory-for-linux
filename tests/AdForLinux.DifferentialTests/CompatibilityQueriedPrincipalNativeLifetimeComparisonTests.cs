using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Read-only operations on the fixture user. Fixture creation/cleanup still
// requires an authorized disposable AD lab. No Save or CommitChanges occurs.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityQueriedPrincipalNativeLifetimeComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    // FindPrincipalByIdentRefHelper passes a SearchResult to GetAsPrincipal.
    // SDSUtils.SearchResultToPrincipal retains UnderlyingSearchObject; the
    // property-specific Load reads that snapshot independently of native entry
    // lifetime. Description must remain cold until the operation under test.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void First_description_read_after_native_close_or_dispose_matches_microsoft(bool disposeNative)
    {
        const string seeded = "differential test user";
        using (var independent = new MsDirectory.DirectoryEntry(DifferentialSettings.PathFor(data.UserDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes))
        {
            Assert.Equal(data.UserDn, Assert.IsType<string>(independent.Properties["distinguishedName"].Value), ignoreCase: true);
            Assert.Equal(seeded, Assert.IsType<string>(independent.Properties["description"].Value));
        }

        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expected = Ms.UserPrincipal.FindByIdentity(expectedContext, Ms.IdentityType.DistinguishedName, data.UserDn);
        using var actual = Ours.UserPrincipal.FindByIdentity(actualContext, Ours.IdentityType.DistinguishedName, data.UserDn);
        Assert.NotNull(expected);
        Assert.NotNull(actual);
        var leftNative = Assert.IsType<MsDirectory.DirectoryEntry>(expected.GetUnderlyingObject());
        var rightNative = Assert.IsType<OurDirectory.DirectoryEntry>(actual.GetUnderlyingObject());
        Assert.Equal(data.UserDn, Assert.IsType<string>(leftNative.Properties["distinguishedName"].Value), ignoreCase: true);
        Assert.Equal(data.UserDn, Assert.IsType<string>(rightNative.Properties["distinguishedName"].Value), ignoreCase: true);
        Assert.Equal(seeded, Assert.IsType<string>(leftNative.Properties["description"].Value));
        Assert.Equal(seeded, Assert.IsType<string>(rightNative.Properties["description"].Value));
        Assert.Same(leftNative, expected.GetUnderlyingObject());
        Assert.Same(rightNative, actual.GetUnderlyingObject());

        // Native entries remain owned by their principals: do not introduce a
        // separate using declaration. Dispose here is the explicit test action;
        // eventual principal cleanup may safely dispose its entry again.
        if (disposeNative)
        {
            leftNative.Dispose();
            rightNative.Dispose();
        }
        else
        {
            leftNative.Close();
            rightNative.Close();
        }

        Assert.Same(expectedContext, expected.Context);
        Assert.Same(actualContext, actual.Context);
        var leftIdentity = ReferenceEquals(leftNative, expected.GetUnderlyingObject());
        var rightIdentity = ReferenceEquals(rightNative, actual.GetUnderlyingObject());
        Assert.True(leftIdentity);
        string? leftDescription = null;
        string? rightDescription = null;
        var leftError = Record.Exception(() => { leftDescription = expected.Description; });
        var rightError = Record.Exception(() => { rightDescription = actual.Description; });
        Assert.Null(leftError);
        Assert.Equal(seeded, leftDescription);
        if (!disposeNative)
        {
            // Close permits native rebinding, so both providers must establish
            // a successful first read independently of the disposed case.
            Assert.Null(rightError);
            Assert.Equal(seeded, rightDescription);
        }
        new Comparison($"Queried principal first Description after native dispose={disposeNative}")
            .Check("retained native wrapper identity", leftIdentity, rightIdentity)
            .Check("getter exception", leftError?.GetType().Name, rightError?.GetType().Name)
            .Check("getter exception parameter", (leftError as ArgumentException)?.ParamName,
                (rightError as ArgumentException)?.ParamName)
            .Check("description", leftDescription, rightDescription)
            .Assert();
    }
}
