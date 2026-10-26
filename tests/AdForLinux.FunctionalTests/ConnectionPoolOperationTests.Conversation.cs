using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class ConversationFixture : IDisposable
    {
        internal readonly List<string> Trace = [];
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal ConversationTransport Transport;
        internal int Acquisitions, Creations;
        internal ConversationFixture() => Transport = new(Trace);
        internal LdapConnectionProvider.Session Acquire()
        {
            Acquisitions++;
            var options = new LdapConnectionOptions { Host = "recording.invalid" };
            return new(Pool.Acquire(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None), () =>
            {
                if (Creations++ != 0) Transport = new(Trace);
                return new(Transport, Transport, options, new LdapAuthenticationSource(options), ReferralChasingOption.None);
            }, reusable: true));
        }
        public void Dispose() => Pool.Dispose();
    }
    private sealed class ConversationTransport(List<string> trace) : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        public LdapTransportCapabilities Capabilities { get; set; } = LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch | LdapTransportCapabilities.Modify;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        internal Queue<LdapSearchEvent> Events = new();
        internal int Pages, Reads, Writes;
        internal TimeSpan OpenBudget, WriteBudget;
        internal readonly List<TimeSpan> ReadBudgets = [], PageBudgets = [];
        internal bool CleanupFails;
        internal Action? OnRead;
        internal Func<CancellationToken, ValueTask<LdapSearchEvent>>? PendingRead;
        internal Action<LdapSubmission, CancellationToken>? WriteAction;
        internal LdapResultEnvelope WriteResult = Envelope(ResultCode.Success);
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        { trace.Add("buffered-search"); return new(ResultCode.Success, "", null, command.BaseDn == "" ? [] : [new(command.BaseDn, new(), [])], [], [], []); }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        { token.ThrowIfCancellationRequested(); OpenBudget = command.Timeout; trace.Add("open"); return ValueTask.FromResult<ILdapSearchCursor>(this); }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        { token.ThrowIfCancellationRequested(); ReadBudgets.Add(remaining); Reads++; trace.Add("read"); OnRead?.Invoke(); return PendingRead is null ? ValueTask.FromResult(Events.Dequeue()) : PendingRead(token); }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token)
        { token.ThrowIfCancellationRequested(); PageBudgets.Add(remaining); Pages++; trace.Add("next-page"); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync()
        { trace.Add("cursor-close"); if (CleanupFails) throw new InvalidOperationException("cleanup uncertain"); return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
        {
            WriteBudget = command.Timeout; Writes++; trace.Add("modify");
            if (WriteAction is null) submission.BeforeSend(); else WriteAction(submission, token);
            return ValueTask.FromResult(WriteResult);
        }
        public void Dispose() => trace.Add("session-close");
    }
    private static LdapResultEnvelope Envelope(ResultCode code) => new(code, "DC=matched", "server detail",
        ["ldap://returned.invalid/"], [new("1.2.3", [0, 255], true)]);
    private static LdapSearchCommand SearchCommand() => new("", "(objectClass=*)", ProtocolScope.Subtree, ["cn"], TimeSpan.FromSeconds(10));
    private static LdapModifyCommand ModifyCommand() => new("CN=recording", [new("description", DirectoryAttributeOperation.Replace, [[0, 255]])], TimeSpan.FromSeconds(10), []);

    [Fact]
    public async Task Streaming_holds_one_lease_across_demand_driven_pages_and_preserves_partial_terminal_result()
    {
        using var f = new ConversationFixture();
        var entry = new LdapSearchEvent.Entry(new("CN=first", new() { ["cn"] = [[0, 255]] }, []));
        var partial = Envelope(ResultCode.SizeLimitExceeded);
        f.Transport.Events = new([entry, new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true),
            new LdapSearchEvent.Reference(new(["ldap://reference.invalid/"], [])), new LdapSearchEvent.PageEnd(partial, true)]);
        await using (var stream = LdapConversation.Search(f.Acquire, SearchCommand(), 25).GetAsyncEnumerator())
        {
            Assert.Equal(0, f.Acquisitions); // deferred, no prefetch
            Assert.True(await stream.MoveNextAsync()); Assert.Same(entry, stream.Current);
            Assert.Equal(1, f.Transport.Reads);
            Assert.True(await stream.MoveNextAsync()); Assert.Equal(0, f.Transport.Pages);
            Assert.DoesNotContain("cursor-close", f.Trace);
            Assert.True(await stream.MoveNextAsync()); Assert.Equal(1, f.Transport.Pages);
            Assert.True(await stream.MoveNextAsync());
            Assert.Same(partial, Assert.IsType<LdapSearchEvent.PageEnd>(stream.Current).Result);
            // Stop at final partial envelope. No continuation despite HasMore=true.
        }
        Assert.Equal(1, f.Transport.Pages); Assert.Equal(1, f.Acquisitions);
        Assert.Equal("cursor-close", f.Trace[^1]);
        using var reused = f.Acquire(); Assert.Equal(1, f.Creations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Streaming_early_stop_or_cancellation_between_pages_retires_after_cursor_cleanup(bool cancel)
    {
        using var f = new ConversationFixture(); using var cts = new CancellationTokenSource();
        f.Transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true));
        await using (var stream = LdapConversation.Search(f.Acquire, SearchCommand(), 25, cts.Token).GetAsyncEnumerator())
        {
            Assert.True(await stream.MoveNextAsync());
            if (cancel)
            {
                cts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await stream.MoveNextAsync());
            }
        }
        Assert.Equal(0, f.Transport.Pages);
        Assert.Equal(new[] { "cursor-close", "session-close" }, f.Trace.TakeLast(2));
    }

    [Fact]
    public async Task Cancellation_does_not_release_lease_while_backend_read_is_still_in_flight()
    {
        using var f = new ConversationFixture(); using var cts = new CancellationTokenSource();
        var pending = new TaskCompletionSource<LdapSearchEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Transport.PendingRead = _ => new(pending.Task);
        await using var stream = LdapConversation.Search(f.Acquire, SearchCommand(), cancellationToken: cts.Token).GetAsyncEnumerator();
        var move = stream.MoveNextAsync().AsTask();
        cts.Cancel();
        Assert.False(move.IsCompleted); Assert.DoesNotContain("cursor-close", f.Trace); Assert.DoesNotContain("session-close", f.Trace);
        pending.SetResult(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await move);
        Assert.Equal(new[] { "cursor-close", "session-close" }, f.Trace.TakeLast(2));
    }

    private sealed class ConversationClock : TimeProvider
    {
        internal long Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
    }

    [Fact]
    public async Task Search_forwards_remaining_budget_after_acquisition_and_between_pages()
    {
        using var f = new ConversationFixture(); var clock = new ConversationClock();
        f.Transport.Events = new([new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true),
            new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false)]);
        LdapConnectionProvider.Session Acquire()
        { var lease = f.Acquire(); clock.Ticks += TimeSpan.FromSeconds(9).Ticks; return lease; }
        await using var stream = LdapConversation.Search(Acquire, SearchCommand(), 25, timeProvider: clock).GetAsyncEnumerator();
        Assert.True(await stream.MoveNextAsync());
        Assert.Equal(TimeSpan.FromSeconds(1), f.Transport.OpenBudget);
        Assert.Equal(TimeSpan.FromSeconds(1), f.Transport.ReadBudgets[0]);
        clock.Ticks += TimeSpan.FromMilliseconds(750).Ticks;
        Assert.True(await stream.MoveNextAsync());
        Assert.Equal(TimeSpan.FromMilliseconds(250), Assert.Single(f.Transport.PageBudgets));
        Assert.Equal(TimeSpan.FromMilliseconds(250), f.Transport.ReadBudgets[1]);
        Assert.Equal(1, f.Acquisitions);
    }

    [Theory]
    [InlineData(9, false)]
    [InlineData(10, true)]
    public async Task Write_acquisition_consumes_total_budget_without_replay(int seconds, bool expired)
    {
        using var f = new ConversationFixture(); var clock = new ConversationClock();
        var result = await LdapConversation.Modify(() =>
        { var lease = f.Acquire(); clock.Ticks += TimeSpan.FromSeconds(seconds).Ticks; return lease; },
            ModifyCommand(), timeProvider: clock);
        Assert.Equal(expired ? LdapWriteDisposition.NotSent : LdapWriteDisposition.Completed, result.Disposition);
        Assert.Equal(seconds == 9 ? 1 : 0, f.Transport.Writes);
        if (seconds == 9) Assert.Equal(TimeSpan.FromSeconds(1), f.Transport.WriteBudget);
        else Assert.IsType<TimeoutException>(result.Error);
        Assert.Equal(1, f.Acquisitions);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Streaming_total_deadline_covers_consumer_pause_and_late_native_completion(bool lateRead)
    {
        using var f = new ConversationFixture(); var clock = new ConversationClock();
        f.Transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true));
        if (lateRead) f.Transport.OnRead = () => clock.Ticks = TimeSpan.FromSeconds(2).Ticks;
        await using var stream = LdapConversation.Search(f.Acquire, SearchCommand() with { Timeout = TimeSpan.FromSeconds(1) },
            25, timeProvider: clock).GetAsyncEnumerator();
        if (!lateRead) { Assert.True(await stream.MoveNextAsync()); clock.Ticks = TimeSpan.FromSeconds(2).Ticks; }
        await Assert.ThrowsAsync<TimeoutException>(async () => await stream.MoveNextAsync());
        Assert.Equal(0, f.Transport.Pages);
        Assert.Equal(new[] { "cursor-close", "session-close" }, f.Trace.TakeLast(2));
    }

    [Fact]
    public async Task Streaming_cleanup_failure_still_retires_and_releases_pool_capacity()
    {
        using var f = new ConversationFixture(); f.Transport.CleanupFails = true;
        f.Transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), false));
        var stream = LdapConversation.Search(f.Acquire, SearchCommand()).GetAsyncEnumerator();
        Assert.True(await stream.MoveNextAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await stream.DisposeAsync());
        Assert.Equal(new[] { "cursor-close", "session-close" }, f.Trace.TakeLast(2));
        using var replacement = f.Acquire(); Assert.Equal(2, f.Creations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Write_failure_distinguishes_not_sent_from_unknown_without_replay(bool started)
    {
        using var f = new ConversationFixture();
        f.Transport.WriteAction = (submission, _) => { if (started) submission.BeforeSend(); throw new OperationCanceledException(); };
        var result = await LdapConversation.Modify(f.Acquire, ModifyCommand());
        Assert.Equal(started ? LdapWriteDisposition.Indeterminate : LdapWriteDisposition.NotSent, result.Disposition);
        Assert.Null(result.Result); Assert.IsType<OperationCanceledException>(result.Error);
        Assert.Equal(1, f.Transport.Writes); Assert.Equal(1, f.Acquisitions);
        Assert.Equal("session-close", f.Trace[^1]);
    }

    [Fact]
    public async Task Write_definitive_error_preserves_envelope_when_cancellation_races_response()
    {
        using var f = new ConversationFixture(); using var cts = new CancellationTokenSource();
        f.Transport.WriteResult = Envelope(ResultCode.InsufficientAccessRights);
        f.Transport.WriteAction = (submission, _) => { submission.BeforeSend(); cts.Cancel(); };
        var result = await LdapConversation.Modify(f.Acquire, ModifyCommand(), cts.Token);
        Assert.Equal(LdapWriteDisposition.Completed, result.Disposition);
        Assert.Same(f.Transport.WriteResult, result.Result); Assert.Null(result.Error);
        Assert.Equal(1, f.Transport.Writes);
        using var reused = f.Acquire(); Assert.Equal(1, f.Creations);
    }

    [Fact]
    public async Task Cancellation_during_acquisition_does_not_enter_write_backend()
    {
        using var f = new ConversationFixture(); using var cts = new CancellationTokenSource();
        var result = await LdapConversation.Modify(() => { var lease = f.Acquire(); cts.Cancel(); return lease; }, ModifyCommand(), cts.Token);
        Assert.Equal(LdapWriteDisposition.NotSent, result.Disposition);
        Assert.Equal(0, f.Transport.Writes); Assert.Empty(f.Trace);
    }

    [Fact]
    public async Task Unpaged_continuation_is_rejected_before_exposing_invalid_completion()
    {
        using var f = new ConversationFixture();
        f.Transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true));
        await using var stream = LdapConversation.Search(f.Acquire, SearchCommand()).GetAsyncEnumerator();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await stream.MoveNextAsync());
        Assert.Equal(new[] { "cursor-close", "session-close" }, f.Trace.TakeLast(2));
    }

    [Fact]
    public async Task Conversation_capability_preflight_and_precancel_do_not_submit()
    {
        using var f = new ConversationFixture();
        f.Transport.Capabilities = LdapTransportCapabilities.Search;
        await using var stream = LdapConversation.Search(f.Acquire, SearchCommand()).GetAsyncEnumerator();
        await Assert.ThrowsAsync<PlatformNotSupportedException>(async () => await stream.MoveNextAsync());
        Assert.Empty(f.Trace);
        var result = await LdapConversation.Modify(f.Acquire, ModifyCommand());
        Assert.Equal(LdapWriteDisposition.NotSent, result.Disposition);
        Assert.Equal(0, f.Transport.Writes);
        var acquisitions = f.Acquisitions;
        result = await LdapConversation.Modify(f.Acquire, ModifyCommand(), new CancellationToken(true));
        Assert.Equal(LdapWriteDisposition.NotSent, result.Disposition); Assert.Equal(acquisitions, f.Acquisitions);
    }
}
