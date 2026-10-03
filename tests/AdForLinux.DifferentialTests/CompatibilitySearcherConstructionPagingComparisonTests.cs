using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Context/native searcher initialization can bind. Authorized lab only.
// No Find, Save, or CommitChanges is performed.
[Collection("differential")]
[Trait("Category", "SearcherConstructionPagingLive")]
public sealed class CompatibilitySearcherConstructionPagingComparisonTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Deferred_filter_assignment_preserves_constructor_paging_state(bool constructorFilter)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var leftFilter = new Ms.UserPrincipal(expectedContext);
        using var rightFilter = new Ours.UserPrincipal(actualContext);
        using var expected = constructorFilter ? new Ms.PrincipalSearcher(leftFilter) : new Ms.PrincipalSearcher();
        using var actual = constructorFilter ? new Ours.PrincipalSearcher(rightFilter) : new Ours.PrincipalSearcher();
        if (!constructorFilter)
        {
            Assert.Null(expected.QueryFilter);
            Assert.Null(actual.QueryFilter);
            expected.QueryFilter = leftFilter;
            actual.QueryFilter = rightFilter;
        }
        Assert.Same(leftFilter, expected.QueryFilter);
        Assert.Same(rightFilter, actual.QueryFilter);
        Assert.Same(expectedContext, expected.Context);
        Assert.Same(actualContext, actual.Context);
        var left = Assert.IsType<MsDirectory.DirectorySearcher>(expected.GetUnderlyingSearcher());
        var right = Assert.IsType<OurDirectory.DirectorySearcher>(actual.GetUnderlyingSearcher());
        Assert.NotEmpty(left.PropertiesToLoad);
        Assert.NotEmpty(right.PropertiesToLoad);
        Assert.Equal(constructorFilter ? 256 : 0, left.PageSize);
        var comparison = new Comparison($"Native paging: constructorFilter={constructorFilter}")
            .Check("initial PageSize", left.PageSize, right.PageSize);

        // Once explicitly configured, a native option must survive another
        // public accessor. This is a control for successful native ownership.
        left.PageSize = 37;
        right.PageSize = 37;
        Assert.Same(left, expected.GetUnderlyingSearcher());
        comparison.Check("native identity", true, ReferenceEquals(right, actual.GetUnderlyingSearcher()))
            .Check("explicit PageSize retained", left.PageSize, right.PageSize);
        Assert.Equal(37, left.PageSize);
        comparison.Assert();
    }
}
