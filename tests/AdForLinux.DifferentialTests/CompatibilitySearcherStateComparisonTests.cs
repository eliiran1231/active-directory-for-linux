using System.Reflection;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Setter/getter operations only: never read SearchRoot or execute a search.
[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilitySearcherStateComparisonTests
{
    public static IEnumerable<object[]> TimeoutBoundaries()
    {
        foreach (var property in new[] { "ClientTimeout", "ServerTimeLimit", "ServerPageTimeLimit" })
        foreach (var ticks in new[]
        {
            long.MinValue, -TimeSpan.TicksPerSecond - 1, -TimeSpan.TicksPerSecond,
            -1L, 0L, 1L,
            (long)int.MaxValue * TimeSpan.TicksPerSecond - 1,
            (long)int.MaxValue * TimeSpan.TicksPerSecond,
            (long)int.MaxValue * TimeSpan.TicksPerSecond + 1,
            (long)int.MaxValue * TimeSpan.TicksPerSecond + TimeSpan.TicksPerSecond,
            long.MaxValue,
        })
            yield return new object[] { property, ticks };
    }

    [Theory]
    [MemberData(nameof(TimeoutBoundaries))]
    public void Timeout_boundary_rejection_and_recovery_match_microsoft(string property, long ticks)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var expectedProperty = typeof(Ms.DirectorySearcher).GetProperty(property)!;
        var actualProperty = typeof(Ours.DirectorySearcher).GetProperty(property)!;
        expectedProperty.SetValue(microsoft, TimeSpan.FromSeconds(7));
        actualProperty.SetValue(ours, TimeSpan.FromSeconds(7));
        var comparison = new Comparison($"{property}: ticks={ticks}");

        // Keep the exact tick value, including values that TotalSeconds rounds
        // to Int32.MaxValue. Compare retained state even when assignment fails.
        CompareStep(comparison, "boundary",
            () => expectedProperty.SetValue(microsoft, TimeSpan.FromTicks(ticks)),
            () => actualProperty.SetValue(ours, TimeSpan.FromTicks(ticks)));
        comparison.Check("ticks after boundary", ((TimeSpan)expectedProperty.GetValue(microsoft)!).Ticks,
            ((TimeSpan)actualProperty.GetValue(ours)!).Ticks);
        CompareStep(comparison, "recovery",
            () => expectedProperty.SetValue(microsoft, TimeSpan.FromTicks(12345678)),
            () => actualProperty.SetValue(ours, TimeSpan.FromTicks(12345678)));
        comparison.Check("ticks after recovery", ((TimeSpan)expectedProperty.GetValue(microsoft)!).Ticks,
            ((TimeSpan)actualProperty.GetValue(ours)!).Ticks).Assert();
    }

    [Theory]
    [InlineData("implicit-cache")]
    [InlineData("explicit-cache")]
    [InlineData("scope-reset")]
    [InlineData("scope-rejected")]
    [InlineData("sync-first")]
    [InlineData("page-first")]
    public void Coupled_options_preserve_state_through_rejection_and_reset(string scenario)
    {
        using var microsoft = new Ms.DirectorySearcher();
        using var ours = new Ours.DirectorySearcher();
        var comparison = new Comparison($"Searcher option sequence: {scenario}");
        var expectedView = new Ms.DirectoryVirtualListView(2);
        var actualView = new Ours.DirectoryVirtualListView(2);
        var expectedSync = new Ms.DirectorySynchronization(new byte[] { 4, 5 });
        var actualSync = new Ours.DirectorySynchronization(new byte[] { 4, 5 });

        void Step(string name, Action expected, Action actual)
        {
            CompareStep(comparison, name, expected, actual);
            comparison.Check($"{name}: cache", microsoft.CacheResults, ours.CacheResults)
                .Check($"{name}: scope", (int)microsoft.SearchScope, (int)ours.SearchScope)
                .Check($"{name}: attribute", microsoft.AttributeScopeQuery, ours.AttributeScopeQuery)
                .Check($"{name}: page size", microsoft.PageSize, ours.PageSize)
                .Check($"{name}: VLV present", microsoft.VirtualListView is not null, ours.VirtualListView is not null)
                .Check($"{name}: VLV identity", ReferenceEquals(expectedView, microsoft.VirtualListView), ReferenceEquals(actualView, ours.VirtualListView))
                .Check($"{name}: sync identity", ReferenceEquals(expectedSync, microsoft.DirectorySynchronization), ReferenceEquals(actualSync, ours.DirectorySynchronization));
        }

        if (scenario.EndsWith("cache", StringComparison.Ordinal))
        {
            if (scenario == "explicit-cache")
                Step("explicit default", () => microsoft.CacheResults = true, () => ours.CacheResults = true);
            Step("assign VLV", () => microsoft.VirtualListView = expectedView, () => ours.VirtualListView = actualView);
            Step("enable cache", () => microsoft.CacheResults = true, () => ours.CacheResults = true);
            Step("clear VLV", () => microsoft.VirtualListView = null, () => ours.VirtualListView = null);
            Step("disable cache", () => microsoft.CacheResults = false, () => ours.CacheResults = false);
            Step("reassign VLV", () => microsoft.VirtualListView = expectedView, () => ours.VirtualListView = actualView);
        }
        else if (scenario.StartsWith("scope", StringComparison.Ordinal))
        {
            if (scenario == "scope-rejected")
                Step("explicit default", () => microsoft.SearchScope = Ms.SearchScope.Subtree, () => ours.SearchScope = Ours.SearchScope.Subtree);
            Step("set attribute", () => microsoft.AttributeScopeQuery = "member", () => ours.AttributeScopeQuery = "member");
            Step("clear attribute", () => microsoft.AttributeScopeQuery = null, () => ours.AttributeScopeQuery = null);
            Step("scope one level", () => microsoft.SearchScope = Ms.SearchScope.OneLevel, () => ours.SearchScope = Ours.SearchScope.OneLevel);
            Step("rejected attribute", () => microsoft.AttributeScopeQuery = "member", () => ours.AttributeScopeQuery = "member");
            Step("scope base", () => microsoft.SearchScope = Ms.SearchScope.Base, () => ours.SearchScope = Ours.SearchScope.Base);
            Step("recovered attribute", () => microsoft.AttributeScopeQuery = "member", () => ours.AttributeScopeQuery = "member");
        }
        else
        {
            if (scenario == "page-first")
                Step("initial paging", () => microsoft.PageSize = 5, () => ours.PageSize = 5);
            Step("set sync", () => microsoft.DirectorySynchronization = expectedSync, () => ours.DirectorySynchronization = actualSync);
            Step("set paging", () => microsoft.PageSize = 5, () => ours.PageSize = 5);
            Step("clear paging", () => microsoft.PageSize = 0, () => ours.PageSize = 0);
            Step("retry sync", () => microsoft.DirectorySynchronization = expectedSync, () => ours.DirectorySynchronization = actualSync);
            Step("clear sync", () => microsoft.DirectorySynchronization = null, () => ours.DirectorySynchronization = null);
            Step("recovered paging", () => microsoft.PageSize = 5, () => ours.PageSize = 5);
        }
        comparison.Assert();
    }

    private static void CompareStep(Comparison comparison, string name, Action expected, Action actual)
    {
        var left = Unwrap(Record.Exception(expected));
        var right = Unwrap(Record.Exception(actual));
        comparison.Check($"{name}: exception", left?.GetType().FullName, right?.GetType().FullName)
            .Check($"{name}: parameter", (left as ArgumentException)?.ParamName, (right as ArgumentException)?.ParamName);
    }

    private static Exception? Unwrap(Exception? error) => error is TargetInvocationException invocation
        ? invocation.InnerException : error;
}
