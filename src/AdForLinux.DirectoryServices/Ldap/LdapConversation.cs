using System.DirectoryServices.Protocols;
using System.Runtime.CompilerServices;

namespace AdForLinux.DirectoryServices.Ldap;

internal sealed record LdapResultEnvelope(ResultCode Code, string? MatchedDn, string? Diagnostic,
    string[] Referrals, LdapTransportControl[] Controls);
internal abstract record LdapSearchEvent
{
    internal sealed record Entry(LdapTransportEntry Value) : LdapSearchEvent;
    internal sealed record Reference(LdapTransportReference Value) : LdapSearchEvent;
    internal sealed record PageEnd(LdapResultEnvelope Result, bool HasMore) : LdapSearchEvent;
}

// A cursor owns native message state and opaque paging cookies. Events own copies.
// Read returns exactly one event; EOF without PageEnd is a transport failure.
// Dispose cancels/abandons unfinished work and releases native state, never the lease.
// Open receives the remaining total budget. Each read/page advance receives its
// current remainder, never a fresh page budget; native waits must honor it.
internal interface ILdapSearchCursor : IAsyncDisposable
{
    ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken cancellationToken);
    ValueTask NextPageAsync(TimeSpan remaining, CancellationToken cancellationToken);
}
internal sealed record LdapAttributeChange(string Name, DirectoryAttributeOperation Operation, byte[][] Values);
internal sealed record LdapModifyCommand(string DistinguishedName, LdapAttributeChange[] Changes,
    TimeSpan Timeout, LdapTransportControl[] Controls) : LdapMutationCommand(DistinguishedName, Timeout, Controls);
internal enum LdapWriteDisposition { NotSent, Indeterminate, Completed }
internal sealed record LdapWriteOutcome(LdapWriteDisposition Disposition, LdapResultEnvelope? Result, Exception? Error);
internal sealed class LdapSubmission(Action? beforeMark = null)
{
    private int started, entered;
    internal bool Started => Volatile.Read(ref started) != 0;
    // Call immediately BEFORE entering a native send, not after it returns.
    // Failure after this boundary cannot establish whether the server applied a write.
    internal void BeforeSend()
    {
        if (Interlocked.Exchange(ref entered, 1) != 0)
            throw new InvalidOperationException("A write cannot be submitted twice.");
        beforeMark?.Invoke();
        Volatile.Write(ref started, 1);
    }
}
internal interface ILdapConversationTransport : ILdapRequestTransport
{
    ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken cancellationToken);
    ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken cancellationToken);
}

// Internal extension seam: existing adapters advertise none of these capabilities.
// acquire transfers an exclusive session lease; the caller must not also dispose it.
internal static class LdapConversation
{
    private sealed class OperationBudget(TimeSpan timeout, TimeProvider? timeProvider)
    {
        private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
        private readonly long started = (timeProvider ?? TimeProvider.System).GetTimestamp();
        internal TimeSpan Remaining(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = timeout - clock.GetElapsedTime(started);
            return remaining > TimeSpan.Zero ? remaining : throw new TimeoutException("The LDAP operation deadline expired.");
        }
    }

    internal static IAsyncEnumerable<LdapSearchEvent> Search(
        Func<LdapConnectionProvider.Session> acquire, LdapSearchCommand command, int pageSize = 0,
        CancellationToken cancellationToken = default, TimeProvider? timeProvider = null,
        Func<TimeSpan>? remainingBudget = null)
        => SearchCore(acquire, true, command, pageSize, cancellationToken, timeProvider, remainingBudget);

    // Buffered callers retain the exclusive lease until cursor cleanup AND schema
    // materialization finish. This method owns only the cursor, never the lease.
    internal static IAsyncEnumerable<LdapSearchEvent> SearchBorrowed(
        LdapConnectionProvider.Session lease, LdapSearchCommand command, int pageSize,
        CancellationToken cancellationToken = default, TimeProvider? timeProvider = null,
        Func<TimeSpan>? remainingBudget = null)
        => SearchCore(() => lease, false, command, pageSize, cancellationToken, timeProvider, remainingBudget);

    private static async IAsyncEnumerable<LdapSearchEvent> SearchCore(
        Func<LdapConnectionProvider.Session> acquire, bool ownsLease, LdapSearchCommand command, int pageSize,
        [EnumeratorCancellation] CancellationToken cancellationToken, TimeProvider? timeProvider,
        Func<TimeSpan>? remainingBudget)
    {
        if (pageSize < 0) throw new ArgumentOutOfRangeException(nameof(pageSize));
        ArgumentNullException.ThrowIfNull(command);
        if (command.Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(command.Timeout));
        var budget = new OperationBudget(command.Timeout, timeProvider);
        TimeSpan Remaining()
        {
            var local = budget.Remaining(cancellationToken);
            var external = remainingBudget?.Invoke() ?? local;
            if (external <= TimeSpan.Zero) throw new TimeoutException("The enclosing LDAP operation deadline expired.");
            return external < local ? external : local;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var lease = acquire();
        using var ownedLease = ownsLease ? lease : null;
        ILdapSearchCursor? cursor = null;
        var complete = false;
        var opened = false;
        try
        {
            var transport = lease.ExecuteTransport(t => t);
            var required = LdapTransportCapabilities.StreamingSearch |
                (pageSize == 0 ? LdapTransportCapabilities.None : LdapTransportCapabilities.PagedSearch);
            if (transport is not ILdapConversationTransport conversation || (transport.Capabilities & required) != required)
                throw new PlatformNotSupportedException("Streaming/paging is not implemented by this adapter; no request was sent.");
            var prepared = LdapRequestDispatcher.Prepare(transport, command);
            prepared = prepared with { Timeout = Remaining() };
            opened = true; // Open may send before throwing; cleanup uncertainty retires.
            cursor = await conversation.OpenSearchAsync(prepared, pageSize, cancellationToken).ConfigureAwait(false);
            while (true)
            {
                var item = await cursor.ReadAsync(Remaining(), cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Search ended without a result envelope.");
                Remaining();
                if (item is LdapSearchEvent.PageEnd end)
                {
                    if (pageSize == 0 && end.Result.Code == ResultCode.Success && end.HasMore)
                        throw new InvalidOperationException("Unpaged search returned a continuation.");
                    complete = end.Result.Code != ResultCode.Success || !end.HasMore;
                    if (end.Result.Code is ResultCode.Unavailable or ResultCode.ProtocolError) lease.Invalidate();
                    // Mark terminal before yield: a consumer may stop at this result.
                    yield return end;
                    if (complete) yield break;
                    // Same cursor, opaque cookie, lease and authority; never reacquire/replay.
                    await cursor.NextPageAsync(Remaining(), cancellationToken).ConfigureAwait(false);
                }
                else if (item is LdapSearchEvent.Entry or LdapSearchEvent.Reference) yield return item;
                else throw new InvalidOperationException("Unknown search event.");
            }
        }
        finally
        {
            if (opened && !complete) lease.Invalidate();
            if (cursor is not null)
            {
                try { await cursor.DisposeAsync().ConfigureAwait(false); }
                catch { lease.Invalidate(); throw; }
            }
            // using returns the lease even if cursor cleanup fails.
        }
    }

    internal static ValueTask<LdapWriteOutcome> Modify(Func<LdapConnectionProvider.Session> acquire,
        LdapModifyCommand command, CancellationToken cancellationToken = default, TimeProvider? timeProvider = null)
        => Mutate(acquire, command, cancellationToken, timeProvider);

    internal static async ValueTask<LdapWriteOutcome> Mutate(Func<LdapConnectionProvider.Session> acquire,
        LdapMutationCommand command, CancellationToken cancellationToken = default, TimeProvider? timeProvider = null)
    {
        LdapConnectionProvider.Session? lease = null;
        var submission = new LdapSubmission();
        var attempted = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(command);
            var budget = new OperationBudget(command.Timeout, timeProvider);
            var prepared = LdapMutationCommands.Prepare(command);
            lease = acquire();
            var transport = lease.ExecuteTransport(t => t);
            LdapMutationCommands.RequireCapabilities(transport, prepared);
            prepared = prepared with { Timeout = budget.Remaining(cancellationToken) };
            attempted = true;
            var result = await LdapMutationCommands.SendAsync(transport, prepared, submission, cancellationToken).ConfigureAwait(false);
            if (!submission.Started || result is null) throw new InvalidOperationException("Invalid write completion contract.");
            if (result.Code is ResultCode.Unavailable or ResultCode.ProtocolError) lease.Invalidate();
            // A complete LDAP error is still a known outcome. Do not turn an arrived
            // response into an unknown write merely because cancellation raced it.
            return new(LdapWriteDisposition.Completed, result, null);
        }
        catch (Exception error)
        {
            if (attempted) lease?.Invalidate();
            return new(submission.Started ? LdapWriteDisposition.Indeterminate : LdapWriteDisposition.NotSent, null, error);
        }
        finally { lease?.Dispose(); }
    }
}
