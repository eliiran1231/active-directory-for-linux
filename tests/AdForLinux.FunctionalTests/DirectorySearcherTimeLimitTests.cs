using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectorySearcherTimeLimitTests
{
    [Fact]
    public void Paged_search_applies_page_limit_until_overall_budget_is_smaller()
    {
        var clock = new ManualTimeProvider();
        var budget = new ServerSearchTimeLimitBudget(
            TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(3),
            isPaged: true,
            clock);

        var firstPage = new SearchRequest();
        Assert.True(budget.TryApply(firstPage));
        Assert.Equal(TimeSpan.FromSeconds(3), firstPage.TimeLimit);

        clock.Advance(TimeSpan.FromSeconds(8));

        var lastPage = new SearchRequest();
        Assert.True(budget.TryApply(lastPage));
        Assert.Equal(TimeSpan.FromSeconds(2), lastPage.TimeLimit);
    }

    [Fact]
    public void Paged_search_does_not_send_another_page_after_overall_budget_expires()
    {
        var clock = new ManualTimeProvider();
        var budget = new ServerSearchTimeLimitBudget(
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(30),
            isPaged: true,
            clock);

        Assert.True(budget.TryApply(new SearchRequest()));

        clock.Advance(TimeSpan.FromSeconds(5));

        Assert.False(budget.TryApply(new SearchRequest()));
    }

    [Fact]
    public void Paged_search_resets_page_limit_when_overall_limit_is_unbounded()
    {
        var clock = new ManualTimeProvider();
        var budget = new ServerSearchTimeLimitBudget(
            TimeSpan.FromSeconds(-1),
            TimeSpan.FromSeconds(4),
            isPaged: true,
            clock);

        var firstPage = new SearchRequest();
        Assert.True(budget.TryApply(firstPage));
        Assert.Equal(TimeSpan.FromSeconds(4), firstPage.TimeLimit);

        clock.Advance(TimeSpan.FromMinutes(1));

        var secondPage = new SearchRequest();
        Assert.True(budget.TryApply(secondPage));
        Assert.Equal(TimeSpan.FromSeconds(4), secondPage.TimeLimit);
    }

    [Fact]
    public void Unpaged_search_uses_only_server_time_limit()
    {
        var clock = new ManualTimeProvider();
        var budget = new ServerSearchTimeLimitBudget(
            TimeSpan.FromSeconds(9),
            TimeSpan.FromSeconds(2),
            isPaged: false,
            clock);

        clock.Advance(TimeSpan.FromSeconds(7));

        var request = new SearchRequest();
        Assert.True(budget.TryApply(request));
        Assert.Equal(TimeSpan.FromSeconds(9), request.TimeLimit);
    }

    [Fact]
    public void Unpaged_search_ignores_page_limit_when_overall_limit_is_unbounded()
    {
        var budget = new ServerSearchTimeLimitBudget(
            TimeSpan.FromSeconds(-1),
            TimeSpan.FromSeconds(2),
            isPaged: false,
            new ManualTimeProvider());
        var request = new SearchRequest();

        Assert.True(budget.TryApply(request));
        Assert.Equal(TimeSpan.Zero, request.TimeLimit);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => _timestamp;

        internal void Advance(TimeSpan elapsed) => _timestamp += elapsed.Ticks;
    }
}
