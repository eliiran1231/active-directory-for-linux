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
        Assert.Equal(SuiteCapture.Expected(previous, "assert-equal-expected", 30), SuiteCapture.Expected(Convert.ToInt32(actualProperty.GetValue(ours)), "assert-equal-actual", 30));

        var expected = Record.Exception(() => SetEnum(expectedProperty, microsoft, invalid));
        var actual = Record.Exception(() => SetEnum(actualProperty, ours, invalid));

        CompareDetachedFailure(expected, actual);
        Assert.NotNull(expected);
        Assert.Equal(SuiteCapture.Expected(previous, "assert-equal-expected", 37), SuiteCapture.Expected(Convert.ToInt32(expectedProperty.GetValue(microsoft)), "assert-equal-actual", 37));
        Assert.Equal(SuiteCapture.Expected(previous, "assert-equal-expected", 38), SuiteCapture.Expected(Convert.ToInt32(actualProperty.GetValue(ours)), "assert-equal-actual", 38));
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
            Assert.Equal(SuiteCapture.Expected(expectedProperty.GetValue(microsoft), "assert-equal-expected", 60), SuiteCapture.Expected(actualProperty.GetValue(ours), "assert-equal-actual", 60));
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
            Assert.Equal(SuiteCapture.Expected(17, "assert-equal-expected", 82), SuiteCapture.Expected(microsoft.PageSize, "assert-equal-actual", 82));
            Assert.Equal(SuiteCapture.Expected(17, "assert-equal-expected", 83), SuiteCapture.Expected(ours.PageSize, "assert-equal-actual", 83));
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
            Assert.Equal(SuiteCapture.Expected(0, "assert-equal-expected", 98), SuiteCapture.Expected(microsoft.PageSize, "assert-equal-actual", 98));
            Assert.Equal(SuiteCapture.Expected(0, "assert-equal-expected", 99), SuiteCapture.Expected(ours.PageSize, "assert-equal-actual", 99));
            microsoft.DirectorySynchronization = null;
            ours.DirectorySynchronization = null;
            microsoft.PageSize = ours.PageSize = 17;
        }
        Assert.Equal(SuiteCapture.Expected(microsoft.PageSize, "assert-equal-expected", 104), SuiteCapture.Expected(ours.PageSize, "assert-equal-actual", 104));
        Assert.Equal(SuiteCapture.Expected(microsoft.DirectorySynchronization is null, "assert-equal-expected", 105), SuiteCapture.Expected(ours.DirectorySynchronization is null, "assert-equal-actual", 105));
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
        Assert.Equal(SuiteCapture.Expected(new byte[] { 0, 128, 255 }, "assert-equal-expected", 121), SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-actual", 121));
        Assert.Equal(SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-expected", 122), SuiteCapture.Expected(ours.GetDirectorySynchronizationCookie(), "assert-equal-actual", 122));

        byte[] replacement = [4, 5];
        microsoft.ResetDirectorySynchronizationCookie(replacement);
        ours.ResetDirectorySynchronizationCookie(replacement);
        replacement[0] = 99;
        Assert.Equal(SuiteCapture.Expected(new byte[] { 4, 5 }, "assert-equal-expected", 128), SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-actual", 128));
        Assert.Equal(SuiteCapture.Expected(microsoft.GetDirectorySynchronizationCookie(), "assert-equal-expected", 129), SuiteCapture.Expected(ours.GetDirectorySynchronizationCookie(), "assert-equal-actual", 129));
        microsoft.ResetDirectorySynchronizationCookie();
        ours.ResetDirectorySynchronizationCookie();
        Assert.Empty(microsoft.GetDirectorySynchronizationCookie());
        Assert.Empty(ours.GetDirectorySynchronizationCookie());
        Assert.Equal(SuiteCapture.Expected(new byte[] { 0, 128, 255 }, "assert-equal-expected", 134), SuiteCapture.Expected(expectedCopy.GetDirectorySynchronizationCookie(), "assert-equal-actual", 134));
        Assert.Equal(SuiteCapture.Expected(expectedCopy.GetDirectorySynchronizationCookie(), "assert-equal-expected", 135), SuiteCapture.Expected(actualCopy.GetDirectorySynchronizationCookie(), "assert-equal-actual", 135));
        Assert.Equal(SuiteCapture.Expected((long)expectedCopy.Option, "assert-equal-expected", 136), SuiteCapture.Expected((long)actualCopy.Option, "assert-equal-actual", 136));
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
        Assert.Equal(SuiteCapture.Expected(microsoft.CacheResults, "assert-equal-expected", 179), SuiteCapture.Expected(ours.CacheResults, "assert-equal-actual", 179));
        Assert.Equal(SuiteCapture.Expected(microsoft.VirtualListView is null, "assert-equal-expected", 180), SuiteCapture.Expected(ours.VirtualListView is null, "assert-equal-actual", 180));
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
        Assert.Equal(SuiteCapture.Expected(2, "assert-equal-expected", 198), SuiteCapture.Expected(microsoft.BeforeCount, "assert-equal-actual", 198));
        Assert.Equal(SuiteCapture.Expected(3, "assert-equal-expected", 199), SuiteCapture.Expected(microsoft.AfterCount, "assert-equal-actual", 199));
        Assert.Equal(SuiteCapture.Expected(40, "assert-equal-expected", 200), SuiteCapture.Expected(microsoft.Offset, "assert-equal-actual", 200));
        Assert.Equal(SuiteCapture.Expected(100, "assert-equal-expected", 201), SuiteCapture.Expected(microsoft.ApproximateTotal, "assert-equal-actual", 201));
        Assert.Equal(SuiteCapture.Expected(40, "assert-equal-expected", 202), SuiteCapture.Expected(microsoft.TargetPercentage, "assert-equal-actual", 202));
        Assert.Equal(SuiteCapture.Expected(microsoft.BeforeCount, "assert-equal-expected", 203), SuiteCapture.Expected(ours.BeforeCount, "assert-equal-actual", 203));
        Assert.Equal(SuiteCapture.Expected(microsoft.AfterCount, "assert-equal-expected", 204), SuiteCapture.Expected(ours.AfterCount, "assert-equal-actual", 204));
        Assert.Equal(SuiteCapture.Expected(microsoft.Offset, "assert-equal-expected", 205), SuiteCapture.Expected(ours.Offset, "assert-equal-actual", 205));
        Assert.Equal(SuiteCapture.Expected(microsoft.ApproximateTotal, "assert-equal-expected", 206), SuiteCapture.Expected(ours.ApproximateTotal, "assert-equal-actual", 206));
        Assert.Equal(SuiteCapture.Expected(microsoft.TargetPercentage, "assert-equal-expected", 207), SuiteCapture.Expected(ours.TargetPercentage, "assert-equal-actual", 207));
    }

    private static void SetEnum(PropertyInfo property, object target, int value) =>
        property.SetValue(target, Enum.ToObject(property.PropertyType, value));

    private static void CompareDetachedFailure(Exception? expected, Exception? actual)
    {
        if (expected is TargetInvocationException expectedInvocation) expected = expectedInvocation.InnerException;
        if (actual is TargetInvocationException actualInvocation) actual = actualInvocation.InnerException;
        Assert.Equal(SuiteCapture.Expected(expected?.GetType(), "assert-equal-expected", 217), SuiteCapture.Expected(actual?.GetType(), "assert-equal-actual", 217));
        if (expected is ArgumentException expectedArgument)
            Assert.Equal(SuiteCapture.Expected(expectedArgument.ParamName, "assert-equal-expected", 219), SuiteCapture.Expected(Assert.IsAssignableFrom<ArgumentException>(actual).ParamName, "assert-equal-actual", 219));
    }
}
