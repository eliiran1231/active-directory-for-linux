using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Requires a live container, but only changes its local enumeration filter.
// No directory objects or attributes are created, modified, or deleted.
public sealed class SchemaFilterBindingComparisonTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Schema_filters_share_parent_binding_state(bool reuseChildren)
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        var expectedChildren = microsoft.Children;
        var actualChildren = ours.Children;
        var expectedFirst = expectedChildren.SchemaFilter;
        var actualFirst = actualChildren.SchemaFilter;
        var expectedSecond = (reuseChildren ? expectedChildren : microsoft.Children).SchemaFilter;
        var actualSecond = (reuseChildren ? actualChildren : ours.Children).SchemaFilter;
        var comparison = new Comparison($"SchemaFilter sharing, reuse Children = {reuseChildren}")
            .Check("getter reuses wrapper", ReferenceEquals(expectedFirst, expectedSecond),
                ReferenceEquals(actualFirst, actualSecond));

        expectedFirst.Clear();
        actualFirst.Clear();
        expectedFirst.Add("group");
        actualFirst.Add("group");
        comparison.Check("second filter after first.Add", Snapshot(expectedSecond), Snapshot(actualSecond));
        comparison.Check("new Children filter after first.Add", Snapshot(microsoft.Children.SchemaFilter),
            Snapshot(ours.Children.SchemaFilter));

        // Mutate through the second wrapper and observe the original wrapper.
        // Clear+Add works even when a broken implementation lost the first Add.
        expectedSecond.Clear();
        actualSecond.Clear();
        expectedSecond.Add("user");
        actualSecond.Add("user");
        comparison.Check("first filter after second.Add", Snapshot(expectedFirst), Snapshot(actualFirst));
        expectedSecond.Clear();
        actualSecond.Clear();
        comparison.Check("first filter after second.Clear", Snapshot(expectedFirst), Snapshot(actualFirst));
        comparison.Assert();
    }

    [Fact]
    public void Independently_opened_entries_keep_independent_filters_control()
    {
        using var microsoft = MicrosoftEntry();
        using var microsoftOther = MicrosoftEntry();
        using var ours = OurEntry();
        using var ourOther = OurEntry();
        var expectedFirst = microsoft.Children.SchemaFilter;
        var expectedOther = microsoftOther.Children.SchemaFilter;
        var actualFirst = ours.Children.SchemaFilter;
        var actualOther = ourOther.Children.SchemaFilter;
        expectedFirst.Clear();
        actualFirst.Clear();
        expectedOther.Clear();
        actualOther.Clear();
        expectedFirst.Add("group");
        actualFirst.Add("group");

        Assert.Equal(Snapshot(expectedFirst), Snapshot(actualFirst));
        Assert.Empty(Snapshot(expectedOther));
        Assert.Equal(Snapshot(expectedOther), Snapshot(actualOther));
    }

    private static string Snapshot(IEnumerable filter) => string.Join("|", filter.Cast<string?>());

    private static Ms.DirectoryEntry MicrosoftEntry() => new(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry() => new(DifferentialSettings.PathFor(DifferentialSettings.UsersContainer),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
}
