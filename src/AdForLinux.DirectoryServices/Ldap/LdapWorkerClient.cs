using System.Diagnostics;

namespace AdForLinux.DirectoryServices.Ldap;

// The retirement action owns pidfd kill/nonblocking reap. It must never wait for
// helper cleanup. No proxy replays a request or reconnects a retired worker.
internal sealed class LdapWorkerClient(Stream channel, Action retireWorker) : IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private long nextId;
    private int retired;
    internal IReadOnlyList<ILdapRequestTransport> Sessions { get; private set; } = [];
    internal static async Task<LdapWorkerClient> StartAsync(Stream channel, Action retireWorker,
        LdapWorkerStart profile, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        LdapWorkerProtocol.ValidateStart(profile);
        var client = new LdapWorkerClient(channel, retireWorker);
        try
        {
            var frame = await client.CallAsync(0, "START", profile, timeout, cancellationToken).ConfigureAwait(false);
            client.Expect(frame, "READY");
            var ready = client.Decode<LdapWorkerReady>(frame);
            var known = Enum.GetValues<LdapTransportCapabilities>().Aggregate(LdapTransportCapabilities.None, (all, value) => all | value);
            if (ready.Capabilities.Length != profile.SessionCount || ready.Capabilities.Any(value =>
                (value & ~known) != 0 || (value & LdapTransportCapabilities.ProtocolsConnection) != 0))
                throw new InvalidDataException("Invalid worker capabilities or session count.");
            client.Sessions = ready.Capabilities.Select((capabilities, index) =>
                (ILdapRequestTransport)new Proxy(client, index, capabilities, profile.Timeout)).ToArray();
            return client;
        }
        catch { client.Dispose(); throw; }
    }
    internal void Expect(LdapWorkerFrame frame, string kind)
    {
        if (frame.Kind != kind || (kind == "OK" && frame.Payload.ValueKind != System.Text.Json.JsonValueKind.Null)) { Dispose(); throw new InvalidDataException("Unexpected worker response."); }
    }
    private T Decode<T>(LdapWorkerFrame frame)
    {
        try
        {
            object value = LdapWorkerProtocol.Payload<T>(frame)!;
            value = value switch
            {
                LdapSearchResult result => result with { Entries = result.Entries.Select(Entry).ToArray(),
                    References = result.References.Select(Reference).ToArray(), Referrals = Texts(result.Referrals), Controls = Controls(result.Controls) },
                LdapTransportEntry entry => Entry(entry),
                LdapTransportReference reference => Reference(reference),
                LdapResultEnvelope result => Envelope(result),
                LdapSearchEvent.PageEnd page => page with { Result = Envelope(page.Result) },
                LdapWorkerReady ready when ready.Capabilities is not null => ready,
                _ => throw new InvalidDataException("Invalid worker response payload.")
            };
            return (T)value;
        }
        catch { Dispose(); throw; }
    }
    private static string Text(string text) => text ?? throw new InvalidDataException("Null worker string.");
    private static string[] Texts(string[] texts) => texts.Select(Text).ToArray();
    private static LdapTransportControl[] Controls(LdapTransportControl[] controls) => controls.Select(control =>
        LdapControlCodec.Snapshot(control with { Oid = Text(control.Oid) })).ToArray();
    private static LdapTransportEntry Entry(LdapTransportEntry entry) => entry with
    {
        DistinguishedName = Text(entry.DistinguishedName), Controls = Controls(entry.Controls),
        Attributes = entry.Attributes.ToDictionary(pair => Text(pair.Key), pair => pair.Value.Select(value =>
            value ?? throw new InvalidDataException("Null worker value.")).ToArray(), StringComparer.OrdinalIgnoreCase)
    };
    private static LdapTransportReference Reference(LdapTransportReference reference) => reference with
    { Urls = Texts(reference.Urls), Controls = Controls(reference.Controls) };
    private static LdapResultEnvelope Envelope(LdapResultEnvelope result) => result with
    { Referrals = Texts(result.Referrals), Controls = Controls(result.Controls) };
    private static TimeSpan Remaining(long started, TimeSpan timeout)
    {
        var value = timeout - Stopwatch.GetElapsedTime(started);
        return value > TimeSpan.Zero ? value : throw new TimeoutException("Worker preparation deadline expired.");
    }
    private async Task<LdapWorkerFrame> CallAsync<T>(int session, string kind, T payload, TimeSpan timeout,
        CancellationToken token, LdapSubmission? submission = null)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromHours(1)) throw new ArgumentOutOfRangeException(nameof(timeout));
        var started = Stopwatch.GetTimestamp();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout);
        var acquired = false;
        try
        {
            await gate.WaitAsync(deadline.Token).ConfigureAwait(false); acquired = true;
            ObjectDisposedException.ThrowIf(Volatile.Read(ref retired) != 0, this);
            var remaining = timeout - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Worker request deadline expired.");
            var id = checked(++nextId);
            await Bounded(LdapWorkerProtocol.WriteAsync(channel,
                LdapWorkerProtocol.Frame(id, session, kind, remaining, payload), deadline.Token).AsTask(), deadline.Token).ConfigureAwait(false);
            var reply = await Receive(id, session, deadline.Token).ConfigureAwait(false);
            if (reply.Kind == "PREPARED")
            {
                if (reply.Payload.ValueKind != System.Text.Json.JsonValueKind.Null || submission is null) throw new InvalidDataException("Unexpected write preparation.");
                deadline.Token.ThrowIfCancellationRequested();
                submission.BeforeSend(); // conservative uncertainty starts BEFORE GO can escape
                await Bounded(LdapWorkerProtocol.WriteAsync(channel,
                    LdapWorkerProtocol.Frame<object?>(id, session, "GO", TimeSpan.Zero, null), deadline.Token).AsTask(), deadline.Token).ConfigureAwait(false);
                reply = await Receive(id, session, deadline.Token).ConfigureAwait(false);
                if (reply.Kind == "PREPARED") throw new InvalidDataException("Duplicate write preparation.");
            }
            if (reply.Kind == "ERROR")
            {
                var error = LdapWorkerProtocol.Payload<LdapWorkerFailure>(reply);
                throw error.Category == "unsupported" ? new PlatformNotSupportedException("Worker capability unavailable.")
                    : new IOException(error.Category.StartsWith("native-", StringComparison.Ordinal) &&
                        int.TryParse(error.Category.AsSpan(7), out var status) && status is >= 2 and <= 13
                        ? "Worker native operation failed (status " + status + ")." : error.Category is "marshal" or "library" or "argument" or "state"
                            ? "Worker operation failed (" + error.Category + ")." : "Worker operation failed.");
            }
            if (submission is not null && !submission.Started) throw new InvalidDataException("Write completed without the submission handshake.");
            // This complete, validated response is accepted. Do not turn it into
            // cancellation if the token races after arrival.
            return reply;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { Dispose(); throw new TimeoutException("Worker request deadline expired."); }
        catch { Dispose(); throw; }
        finally { if (acquired) gate.Release(); }
    }
    private async Task<LdapWorkerFrame> Receive(long id, int session, CancellationToken token)
    {
        var reply = await LdapWorkerProtocol.ReadAsync(channel, token).AsTask().WaitAsync(token).ConfigureAwait(false);
        if (reply.Id != id || reply.Session != session || reply.TimeoutTicks != 0) throw new InvalidDataException("Worker response identity mismatch.");
        return reply;
    }
    private static async Task Bounded(Task task, CancellationToken token) => await task.WaitAsync(token).ConfigureAwait(false);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref retired, 1) != 0) return;
        try { retireWorker(); } finally { channel.Dispose(); }
    }
    private sealed class Proxy(LdapWorkerClient owner, int session, LdapTransportCapabilities capabilities, TimeSpan timeout)
        : ILdapConversationTransport, ILdapMutationTransport
    {
        public LdapTransportCapabilities Capabilities => capabilities;
        public TimeSpan Timeout => timeout;
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
        {
            var started = Stopwatch.GetTimestamp();
            var prepared = LdapRequestDispatcher.Prepare(this, command);
            var frame = owner.CallAsync(session, "SEARCH", prepared, Remaining(started, command.Timeout), cancellationToken).GetAwaiter().GetResult();
            owner.Expect(frame, "SEARCH_RESULT"); return owner.Decode<LdapSearchResult>(frame);
        }
        public async ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken cancellationToken)
        {
            var started = Stopwatch.GetTimestamp();
            var prepared = LdapRequestDispatcher.Prepare(this, command);
            var frame = await owner.CallAsync(session, "OPEN", new LdapWorkerOpen(prepared, pageSize), Remaining(started, command.Timeout), cancellationToken).ConfigureAwait(false);
            owner.Expect(frame, "OK"); return new Cursor(owner, session, started, command.Timeout);
        }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken cancellationToken)
            => MutateAsync(command, submission, cancellationToken);
        public async ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken cancellationToken)
        {
            var started = Stopwatch.GetTimestamp();
            LdapMutationCommands.RequireCapabilities(this, command); command = LdapMutationCommands.Prepare(command);
            var frame = command switch
            {
                LdapModifyCommand modify => await owner.CallAsync(session, "MODIFY", modify, Remaining(started, command.Timeout), cancellationToken, submission).ConfigureAwait(false),
                LdapAddCommand add => await owner.CallAsync(session, "ADD", add, Remaining(started, command.Timeout), cancellationToken, submission).ConfigureAwait(false),
                LdapDeleteCommand delete => await owner.CallAsync(session, "DELETE", delete, Remaining(started, command.Timeout), cancellationToken, submission).ConfigureAwait(false),
                LdapModifyDnCommand rename => await owner.CallAsync(session, "RENAME", rename, Remaining(started, command.Timeout), cancellationToken, submission).ConfigureAwait(false),
                _ => throw new PlatformNotSupportedException("Unknown worker mutation.")
            };
            owner.Expect(frame, "WRITE_RESULT"); return owner.Decode<LdapResultEnvelope>(frame);
        }
    }
    private sealed class Cursor(LdapWorkerClient owner, int session, long opened, TimeSpan initialBudget) : ILdapSearchCursor
    {
        private int disposed;
        private long lastStarted = opened;
        private TimeSpan lastBudget = initialBudget;
        public async ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            lastStarted = Stopwatch.GetTimestamp(); lastBudget = remaining;
            var frame = await owner.CallAsync<object?>(session, "READ", null, remaining, cancellationToken).ConfigureAwait(false);
            return frame.Kind switch
            {
                "ENTRY" => new LdapSearchEvent.Entry(owner.Decode<LdapTransportEntry>(frame)),
                "REFERENCE" => new LdapSearchEvent.Reference(owner.Decode<LdapTransportReference>(frame)),
                "PAGE" => owner.Decode<LdapSearchEvent.PageEnd>(frame),
                _ => throw Unexpected()
            };
        }
        public async ValueTask NextPageAsync(TimeSpan remaining, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            lastStarted = Stopwatch.GetTimestamp(); lastBudget = remaining;
            var frame = await owner.CallAsync<object?>(session, "NEXT", null, remaining, cancellationToken).ConfigureAwait(false); owner.Expect(frame, "OK");
        }
        private Exception Unexpected()
        { owner.Dispose(); return new InvalidDataException("Unexpected worker cursor event."); }
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try
            {
                var frame = await owner.CallAsync<object?>(session, "CLOSE", null,
                    Remaining(lastStarted, lastBudget), CancellationToken.None).ConfigureAwait(false);
                owner.Expect(frame, "OK");
            }
            catch { owner.Dispose(); throw; }
        }
    }
}
internal sealed record LdapWorkerOpen(LdapSearchCommand Command, int PageSize);
