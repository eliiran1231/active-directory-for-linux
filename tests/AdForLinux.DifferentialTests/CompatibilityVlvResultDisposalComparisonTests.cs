using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Read-only bounded fixture searches; execute only in an authorized lab with
// server-side sort and VLV support. Fixture setup/cleanup can write to AD.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityVlvResultDisposalComparisonTests(TestDataFixture data)
    : IClassFixture<TestDataFixture>
{
    // Microsoft retains searchResult until cursor EOF or the next search.
    // VirtualListView's getter asks that collection for its response; the
    // response accessor explicitly rejects disposal. This is independent of
    // arithmetic or cookie/context payload values.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void View_getter_after_result_disposal_matches_exhaustion_state(bool exhaust)
    {
        var knownDns = new[] { data.UserDn, data.UnsetUserDn, data.GroupDn };
        var filter = $"(|(sAMAccountName={data.UserName})(sAMAccountName={data.UnsetUserName})(sAMAccountName={data.GroupName}))";
        using var expectedRoot = new Ms.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
        using var actualRoot = new Ours.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);

        // Prove the exact candidate set and successful sorting separately. These
        // are different searchers/results, so they cannot exhaust the tested cursor.
        using (var leftControl = new Ms.DirectorySearcher(expectedRoot, filter)
        {
            SearchScope = Ms.SearchScope.OneLevel, Sort = new Ms.SortOption("cn", Ms.SortDirection.Ascending),
        })
        using (var rightControl = new Ours.DirectorySearcher(actualRoot, filter)
        {
            SearchScope = Ours.SearchScope.OneLevel, Sort = new Ours.SortOption("cn", Ours.SortDirection.Ascending),
        })
        using (var leftResults = leftControl.FindAll())
        using (var rightResults = rightControl.FindAll())
        {
            var leftDns = leftResults.Cast<Ms.SearchResult>().Select(row => (string)row.Properties["distinguishedName"][0]!).ToArray();
            var rightDns = rightResults.Cast<Ours.SearchResult>().Select(row => (string)row.Properties["distinguishedName"][0]!).ToArray();
            Assert.Equal(3, leftDns.Length);
            Assert.Equal(3, rightDns.Length);
            Assert.True(knownDns.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(leftDns));
            Assert.True(knownDns.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(rightDns));
            Assert.Equal(leftDns, rightDns, StringComparer.OrdinalIgnoreCase);

            // Independently establish VLV support and the one-row window for
            // each case, without consuming the later candidate collection.
            var leftControlView = new Ms.DirectoryVirtualListView(0, 0, 1);
            var rightControlView = new Ours.DirectoryVirtualListView(0, 0, 1);
            leftControl.VirtualListView = leftControlView;
            rightControl.VirtualListView = rightControlView;
            using var leftWindow = leftControl.FindAll();
            using var rightWindow = rightControl.FindAll();
            var leftWindowDns = leftWindow.Cast<Ms.SearchResult>()
                .Select(row => (string)row.Properties["distinguishedName"][0]!).ToArray();
            var rightWindowDns = rightWindow.Cast<Ours.SearchResult>()
                .Select(row => (string)row.Properties["distinguishedName"][0]!).ToArray();
            Assert.Equal(leftDns[0], Assert.Single(leftWindowDns), ignoreCase: true);
            Assert.Equal(rightDns[0], Assert.Single(rightWindowDns), ignoreCase: true);
            Assert.Equal(3, leftControlView.ApproximateTotal);
            Assert.Equal(3, rightControlView.ApproximateTotal);
        }

        var leftView = new Ms.DirectoryVirtualListView(0, 0, 1);
        var rightView = new Ours.DirectoryVirtualListView(0, 0, 1);
        using var expected = new Ms.DirectorySearcher(expectedRoot, filter)
        {
            SearchScope = Ms.SearchScope.OneLevel,
            Sort = new Ms.SortOption("cn", Ms.SortDirection.Ascending), VirtualListView = leftView,
        };
        using var actual = new Ours.DirectorySearcher(actualRoot, filter)
        {
            SearchScope = Ours.SearchScope.OneLevel,
            Sort = new Ours.SortOption("cn", Ours.SortDirection.Ascending), VirtualListView = rightView,
        };
        using var left = expected.FindAll();
        using var right = actual.FindAll();
        var leftCursor = left.GetEnumerator();
        var rightCursor = right.GetEnumerator();
        try
        {
            Assert.True(leftCursor.MoveNext());
            Assert.True(rightCursor.MoveNext());
            var leftRow = Assert.IsType<Ms.SearchResult>(leftCursor.Current);
            var rightRow = Assert.IsType<Ours.SearchResult>(rightCursor.Current);
            var leftDn = Assert.IsType<string>(leftRow.Properties["distinguishedName"][0]);
            var rightDn = Assert.IsType<string>(rightRow.Properties["distinguishedName"][0]);
            Assert.Contains(leftDn, knownDns, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(leftDn, rightDn, ignoreCase: true);
            if (exhaust)
            {
                // The VLV window contains exactly one row. This final advance
                // reaches EOF and clears Microsoft's retained response pointer.
                Assert.False(leftCursor.MoveNext());
                Assert.False(rightCursor.MoveNext());
                Assert.Equal(3, leftView.ApproximateTotal);
            }
            // Do not read Count or either searcher's VirtualListView getter
            // here: the partial row must retain its unexhausted response state.
        }
        finally
        {
            try { (leftCursor as IDisposable)?.Dispose(); }
            finally { (rightCursor as IDisposable)?.Dispose(); }
        }
        left.Dispose();
        right.Dispose();

        Ms.DirectoryVirtualListView? leftRead = null;
        Ours.DirectoryVirtualListView? rightRead = null;
        var leftError = Record.Exception(() => { leftRead = expected.VirtualListView; });
        var rightError = Record.Exception(() => { rightRead = actual.VirtualListView; });
        if (exhaust)
        {
            Assert.Null(leftError);
            Assert.Same(leftView, leftRead);
        }
        else
        {
            var failure = Assert.IsType<ObjectDisposedException>(leftError);
            Assert.Equal(nameof(Ms.SearchResultCollection), failure.ObjectName);
        }

        // Capture the failure before changing options. Clearing the option must
        // allow the same searchers' getters to recover without another search.
        expected.VirtualListView = null;
        actual.VirtualListView = null;
        Assert.Null(expected.VirtualListView);
        Assert.Null(actual.VirtualListView);
        new Comparison($"VLV response getter after result disposal: exhausted={exhaust}")
            .Check("getter exception", leftError?.GetType().Name, rightError?.GetType().Name)
            .Check("disposed object", (leftError as ObjectDisposedException)?.ObjectName,
                (rightError as ObjectDisposedException)?.ObjectName)
            .Check("returned supplied view", ReferenceEquals(leftView, leftRead), ReferenceEquals(rightView, rightRead))
            .Assert();
    }
}
