using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Native-searcher initialization can bind. No Find, Save, or directory write
// occurs; execute only in the separately authorized disposable lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityAdvancedFilterOverrideComparisonTests
{
    // Microsoft query-state access reads its stored rosf directly, rather than
    // dispatching the public virtual AdvancedSearchFilter getter.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AuthenticablePrincipal.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Query_translation_uses_matching_filter_instance_with_overridden_getter(bool useAlternate)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expected = new MicrosoftUser(expectedContext);
        using var actual = new OurUser(actualContext);
        using var expectedSearcher = new Ms.PrincipalSearcher(expected);
        using var actualSearcher = new Ours.PrincipalSearcher(actual);

        // Establish valid custom-user translation before configuring criteria.
        var expectedUnfiltered = ExpectedFilter();
        var actualUnfiltered = ActualFilter();
        Assert.False(string.IsNullOrEmpty(expectedUnfiltered));
        Assert.Equal(expectedUnfiltered, actualUnfiltered);
        Assert.DoesNotContain("badPwdCount", expectedUnfiltered, StringComparison.OrdinalIgnoreCase);
        Assert.NotSame(expected.BaseFilter, expected.Alternate);
        Assert.NotSame(actual.BaseFilter, actual.Alternate);
        expected.BaseFilter.BadLogonCount(3, Ms.MatchType.Equals);
        actual.BaseFilter.BadLogonCount(3, Ours.MatchType.Equals);
        expected.Alternate.BadLogonCount(7, Ms.MatchType.Equals);
        actual.Alternate.BadLogonCount(7, Ours.MatchType.Equals);

        // With the override returning the base instance, both must use 3 even
        // though a separate normally constructed filter holds 7.
        var expectedBase = ExpectedFilter();
        var actualBase = ActualFilter();
        Assert.Contains("(badPwdCount=3)", expectedBase, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("(badPwdCount=7)", expectedBase, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedBase, actualBase);
        expected.UseAlternate = actual.UseAlternate = useAlternate;
        Assert.Same(useAlternate ? expected.Alternate : expected.BaseFilter, expected.AdvancedSearchFilter);
        Assert.Same(useAlternate ? actual.Alternate : actual.BaseFilter, actual.AdvancedSearchFilter);
        var expectedObserved = ExpectedFilter();
        var actualObserved = ActualFilter();
        Assert.Equal(expectedBase, expectedObserved);

        // Change only virtual dispatch, not either instance's stored criteria.
        // This recovery isolates getter selection from detached-filter storage.
        expected.UseAlternate = actual.UseAlternate = false;
        Assert.Equal(expectedBase, ExpectedFilter());
        Assert.Equal(expectedBase, ActualFilter());
        new Comparison($"AdvancedSearchFilter override; alternate={useAlternate}")
            .Check("native query filter", expectedObserved, actualObserved)
            .Assert();

        string? ExpectedFilter() => Assert.IsType<System.DirectoryServices.DirectorySearcher>(
            expectedSearcher.GetUnderlyingSearcher()).Filter;
        string? ActualFilter() => Assert.IsType<AdForLinux.DirectoryServices.DirectorySearcher>(
            actualSearcher.GetUnderlyingSearcher()).Filter;
    }

    [Ms.DirectoryObjectClass("user")]
    private sealed class MicrosoftUser : Ms.UserPrincipal
    {
        internal MicrosoftUser(Ms.PrincipalContext context) : base(context) => Alternate = new MicrosoftFilters(this);
        internal Ms.AdvancedFilters BaseFilter => base.AdvancedSearchFilter;
        internal Ms.AdvancedFilters Alternate { get; }
        internal bool UseAlternate { get; set; }
        public override Ms.AdvancedFilters AdvancedSearchFilter => UseAlternate ? Alternate : BaseFilter;
    }

    [Ours.DirectoryObjectClass("user")]
    private sealed class OurUser : Ours.UserPrincipal
    {
        internal OurUser(Ours.PrincipalContext context) : base(context) => Alternate = new OurFilters(this);
        internal Ours.AdvancedFilters BaseFilter => base.AdvancedSearchFilter;
        internal Ours.AdvancedFilters Alternate { get; }
        internal bool UseAlternate { get; set; }
        public override Ours.AdvancedFilters AdvancedSearchFilter => UseAlternate ? Alternate : BaseFilter;
    }

    private sealed class MicrosoftFilters(Ms.Principal owner) : Ms.AdvancedFilters(owner);
    private sealed class OurFilters(Ours.Principal owner) : Ours.AdvancedFilters(owner);
}
