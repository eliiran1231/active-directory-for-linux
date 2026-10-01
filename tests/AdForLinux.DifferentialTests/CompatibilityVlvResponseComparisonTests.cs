using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityVlvResponseComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;
    public CompatibilityVlvResponseComparisonTests(TestDataFixture data) => _data = data;

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Actual_sorted_search_response_updates_retained_view_like_microsoft(int offset)
    {
        // Exactly three existing fixture rows: 1/3 and 2/3 exercise percentage
        // rounding, while 3/3 is the exact-boundary control. No synthetic response
        // or assumption about the order of Microsoft's response setters is used.
        var filter = $"(|(sAMAccountName={_data.UserName})(sAMAccountName={_data.UnsetUserName})(sAMAccountName={_data.GroupName}))";
        using var expectedRoot = new Ms.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actualRoot = new Ours.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        var expectedView = new Ms.DirectoryVirtualListView(0, 0, offset);
        var actualView = new Ours.DirectoryVirtualListView(0, 0, offset);
        using var expectedSearcher = new Ms.DirectorySearcher(expectedRoot, filter)
        {
            SearchScope = Ms.SearchScope.OneLevel,
            Sort = new Ms.SortOption("cn", Ms.SortDirection.Ascending), VirtualListView = expectedView,
        };
        using var actualSearcher = new Ours.DirectorySearcher(actualRoot, filter)
        {
            SearchScope = Ours.SearchScope.OneLevel,
            Sort = new Ours.SortOption("cn", Ours.SortDirection.Ascending), VirtualListView = actualView,
        };
        using var expectedResults = expectedSearcher.FindAll();
        using var actualResults = actualSearcher.FindAll();
        // Exhaust both enumerations before inspecting the returned control.
        var expectedNames = expectedResults.Cast<Ms.SearchResult>()
            .Select(row => row.Properties["samaccountname"][0]?.ToString()).ToArray();
        var actualNames = actualResults.Cast<Ours.SearchResult>()
            .Select(row => row.Properties["samaccountname"][0]?.ToString()).ToArray();
        Assert.Single(expectedNames);
        Assert.Equal(expectedNames, actualNames);
        Assert.Equal(3, expectedView.ApproximateTotal);

        var comparison = new Comparison($"Live VLV response at {offset} of three rows");
        Compare(comparison, "retained after exhaustion", expectedView, actualView);
        var expectedRead = expectedSearcher.VirtualListView!;
        var actualRead = actualSearcher.VirtualListView!;
        comparison.Check("getter retains supplied object", ReferenceEquals(expectedView, expectedRead), ReferenceEquals(actualView, actualRead));
        Compare(comparison, "getter after exhaustion", expectedRead, actualRead);
        Compare(comparison, "second getter", expectedSearcher.VirtualListView!, actualSearcher.VirtualListView!);
        comparison.Assert();
    }

    private static void Compare(Comparison comparison, string label, Ms.DirectoryVirtualListView expected, Ours.DirectoryVirtualListView actual) => comparison
        .Check($"{label}: before", expected.BeforeCount, actual.BeforeCount)
        .Check($"{label}: after", expected.AfterCount, actual.AfterCount)
        .Check($"{label}: offset", expected.Offset, actual.Offset)
        .Check($"{label}: total", expected.ApproximateTotal, actual.ApproximateTotal)
        .Check($"{label}: percentage", expected.TargetPercentage, actual.TargetPercentage)
        .Check($"{label}: target", expected.Target, actual.Target)
        .Check($"{label}: context present", expected.DirectoryVirtualListViewContext is not null, actual.DirectoryVirtualListViewContext is not null);
}
