using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// All operations here are detached constructors, getters and setters. No root,
// search execution, directory fixture, native connection or credential is used.
public sealed partial class SearcherValidationContractComparisonTests
{
    [Theory]
    [InlineData("DerefAlias", -1)]
    [InlineData("DerefAlias", 4)]
    [InlineData("ExtendedDN", -2)]
    [InlineData("ExtendedDN", 2)]
    [InlineData("ReferralChasing", 1)]
    [InlineData("ReferralChasing", int.MaxValue)]
    [InlineData("SearchScope", -1)]
    [InlineData("SearchScope", 3)]
    [InlineData("SecurityMasks", 16)]
    [InlineData("SecurityMasks", int.MaxValue)]
    public void Detached_enum_rejection_preserves_previous_value(string property, int invalid)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var expectedProperty = typeof(Ms.DirectorySearcher).GetProperty(property)!;
        var actualProperty = typeof(Ours.DirectorySearcher).GetProperty(property)!;
        var previous = Convert.ToInt32(expectedProperty.GetValue(microsoft));
        Assert.Equal(previous, Convert.ToInt32(actualProperty.GetValue(ours)));

        var expected = Record.Exception(() => SetEnum(expectedProperty, microsoft, invalid));
        var actual = Record.Exception(() => SetEnum(actualProperty, ours, invalid));

        CompareDetachedFailure(expected, actual);
        Assert.NotNull(expected);
        Assert.Equal(previous, Convert.ToInt32(expectedProperty.GetValue(microsoft)));
        Assert.Equal(previous, Convert.ToInt32(actualProperty.GetValue(ours)));
    }

    [Theory]
    [InlineData("ClientTimeout")]
    [InlineData("ServerTimeLimit")]
    [InlineData("ServerPageTimeLimit")]
    public void Detached_time_limits_match_fractional_and_overflow_boundaries(string property)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var expectedProperty = typeof(Ms.DirectorySearcher).GetProperty(property)!;
        var actualProperty = typeof(Ours.DirectorySearcher).GetProperty(property)!;
        foreach (var value in new[] {
            TimeSpan.FromSeconds(-2), TimeSpan.FromSeconds(-1),
            TimeSpan.Zero, TimeSpan.FromTicks(1), TimeSpan.FromMilliseconds(1500),
            TimeSpan.FromSeconds(int.MaxValue), TimeSpan.FromSeconds((long)int.MaxValue + 1),
            TimeSpan.MaxValue })
        {
            var expected = Record.Exception(() => expectedProperty.SetValue(microsoft, value));
            var actual = Record.Exception(() => actualProperty.SetValue(ours, value));
            CompareDetachedFailure(expected, actual);
            Assert.Equal(expectedProperty.GetValue(microsoft), actualProperty.GetValue(ours));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Detached_paging_and_sync_conflicts_preserve_state_and_allow_recovery(bool pagingFirst)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var expectedSync = new Ms.DirectorySynchronization(new byte[] { 0, 255 });
        var actualSync = new Ours.DirectorySynchronization(new byte[] { 0, 255 });
        if (pagingFirst)
        {
            microsoft.PageSize = ours.PageSize = 17;
            var expected = Record.Exception(() => microsoft.DirectorySynchronization = expectedSync);
            var actual = Record.Exception(() => ours.DirectorySynchronization = actualSync);
            Assert.IsType<ArgumentException>(expected);
            CompareDetachedFailure(expected, actual);
            Assert.Null(microsoft.DirectorySynchronization);
            Assert.Null(ours.DirectorySynchronization);
            Assert.Equal(17, microsoft.PageSize);
            Assert.Equal(17, ours.PageSize);
            microsoft.PageSize = ours.PageSize = 0;
            microsoft.DirectorySynchronization = expectedSync;
            ours.DirectorySynchronization = actualSync;
        }
        else
        {
            microsoft.DirectorySynchronization = expectedSync;
            ours.DirectorySynchronization = actualSync;
            var expected = Record.Exception(() => microsoft.PageSize = 17);
            var actual = Record.Exception(() => ours.PageSize = 17);
            Assert.IsType<ArgumentException>(expected);
            CompareDetachedFailure(expected, actual);
            Assert.Same(expectedSync, microsoft.DirectorySynchronization);
            Assert.Same(actualSync, ours.DirectorySynchronization);
            Assert.Equal(0, microsoft.PageSize);
            Assert.Equal(0, ours.PageSize);
            microsoft.DirectorySynchronization = null;
            ours.DirectorySynchronization = null;
            microsoft.PageSize = ours.PageSize = 17;
        }
        Assert.Equal(microsoft.PageSize, ours.PageSize);
        Assert.Equal(microsoft.DirectorySynchronization is null, ours.DirectorySynchronization is null);
    }

    [Fact]
    public void Detached_sync_cookie_and_copy_are_independent_after_reset()
    {
        byte[] expectedInput = [0, 128, 255];
        byte[] actualInput = [0, 128, 255];
        var microsoft = new Ms.DirectorySynchronization(Ms.DirectorySynchronizationOptions.IncrementalValues, expectedInput);
        var ours = new Ours.DirectorySynchronization(Ours.DirectorySynchronizationOptions.IncrementalValues, actualInput);
        var expectedCopy = microsoft.Copy();
        var actualCopy = ours.Copy();

        expectedInput[0] = actualInput[0] = 42;
        microsoft.GetDirectorySynchronizationCookie()[1] = 42;
        ours.GetDirectorySynchronizationCookie()[1] = 42;
        Assert.Equal(new byte[] { 0, 128, 255 }, microsoft.GetDirectorySynchronizationCookie());
        Assert.Equal(microsoft.GetDirectorySynchronizationCookie(), ours.GetDirectorySynchronizationCookie());

        byte[] replacement = [4, 5];
        microsoft.ResetDirectorySynchronizationCookie(replacement);
        ours.ResetDirectorySynchronizationCookie(replacement);
        replacement[0] = 99;
        Assert.Equal(new byte[] { 4, 5 }, microsoft.GetDirectorySynchronizationCookie());
        Assert.Equal(microsoft.GetDirectorySynchronizationCookie(), ours.GetDirectorySynchronizationCookie());
        microsoft.ResetDirectorySynchronizationCookie();
        ours.ResetDirectorySynchronizationCookie();
        Assert.Empty(microsoft.GetDirectorySynchronizationCookie());
        Assert.Empty(ours.GetDirectorySynchronizationCookie());
        Assert.Equal(new byte[] { 0, 128, 255 }, expectedCopy.GetDirectorySynchronizationCookie());
        Assert.Equal(expectedCopy.GetDirectorySynchronizationCookie(), actualCopy.GetDirectorySynchronizationCookie());
        Assert.Equal((long)expectedCopy.Option, (long)actualCopy.Option);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Detached_virtual_list_conflicts_preserve_explicit_cache_intent(bool cacheFirst)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var expectedView = new Ms.DirectoryVirtualListView(2, 3, 7);
        var actualView = new Ours.DirectoryVirtualListView(2, 3, 7);
        if (cacheFirst)
        {
            microsoft.CacheResults = ours.CacheResults = true;
            var expected = Record.Exception(() => microsoft.VirtualListView = expectedView);
            var actual = Record.Exception(() => ours.VirtualListView = actualView);
            Assert.NotNull(expected);
            CompareDetachedFailure(expected, actual);
            Assert.Null(microsoft.VirtualListView);
            Assert.Null(ours.VirtualListView);
            Assert.True(microsoft.CacheResults);
            Assert.True(ours.CacheResults);
            microsoft.CacheResults = ours.CacheResults = false;
            microsoft.VirtualListView = expectedView;
            ours.VirtualListView = actualView;
        }
        else
        {
            microsoft.VirtualListView = expectedView;
            ours.VirtualListView = actualView;
            Assert.False(microsoft.CacheResults);
            Assert.False(ours.CacheResults);
            var expected = Record.Exception(() => microsoft.CacheResults = true);
            var actual = Record.Exception(() => ours.CacheResults = true);
            Assert.NotNull(expected);
            CompareDetachedFailure(expected, actual);
            Assert.Same(expectedView, microsoft.VirtualListView);
            Assert.Same(actualView, ours.VirtualListView);
            microsoft.VirtualListView = null;
            ours.VirtualListView = null;
            microsoft.CacheResults = ours.CacheResults = true;
        }
        Assert.Equal(microsoft.CacheResults, ours.CacheResults);
        Assert.Equal(microsoft.VirtualListView is null, ours.VirtualListView is null);
    }

    [Theory]
    [InlineData("BeforeCount", -1)]
    [InlineData("AfterCount", int.MinValue)]
    [InlineData("Offset", -1)]
    [InlineData("ApproximateTotal", -1)]
    [InlineData("TargetPercentage", -1)]
    [InlineData("TargetPercentage", 101)]
    public void Detached_virtual_list_rejected_setter_preserves_coupled_state(string property, int invalid)
    {
        var microsoft = new Ms.DirectoryVirtualListView(2, 3, 7) { ApproximateTotal = 100, TargetPercentage = 40 };
        var ours = new Ours.DirectoryVirtualListView(2, 3, 7) { ApproximateTotal = 100, TargetPercentage = 40 };
        var expected = Record.Exception(() => typeof(Ms.DirectoryVirtualListView).GetProperty(property)!.SetValue(microsoft, invalid));
        var actual = Record.Exception(() => typeof(Ours.DirectoryVirtualListView).GetProperty(property)!.SetValue(ours, invalid));
        Assert.NotNull(expected);
        CompareDetachedFailure(expected, actual);
        Assert.Equal(2, microsoft.BeforeCount);
        Assert.Equal(3, microsoft.AfterCount);
        Assert.Equal(40, microsoft.Offset);
        Assert.Equal(100, microsoft.ApproximateTotal);
        Assert.Equal(40, microsoft.TargetPercentage);
        Assert.Equal(microsoft.BeforeCount, ours.BeforeCount);
        Assert.Equal(microsoft.AfterCount, ours.AfterCount);
        Assert.Equal(microsoft.Offset, ours.Offset);
        Assert.Equal(microsoft.ApproximateTotal, ours.ApproximateTotal);
        Assert.Equal(microsoft.TargetPercentage, ours.TargetPercentage);
    }

    private static void SetEnum(PropertyInfo property, object target, int value) =>
        property.SetValue(target, Enum.ToObject(property.PropertyType, value));

    private static void CompareDetachedFailure(Exception? expected, Exception? actual)
    {
        if (expected is TargetInvocationException expectedInvocation) expected = expectedInvocation.InnerException;
        if (actual is TargetInvocationException actualInvocation) actual = actualInvocation.InnerException;
        Assert.Equal(expected?.GetType(), actual?.GetType());
        if (expected is ArgumentException expectedArgument)
            Assert.Equal(expectedArgument.ParamName, Assert.IsAssignableFrom<ArgumentException>(actual).ParamName);
    }
}
