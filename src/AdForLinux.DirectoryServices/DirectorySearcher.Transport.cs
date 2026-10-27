using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectorySearcher
{
    private SearchResult[] ReadNeutralBuffered(DirectoryEntry.ConnectionLease lease,
        ILdapRequestTransport transport, SearchResultOrigin origin, SearchRequest request,
        int pageSize, TimeProvider clock, long started, int maximumResults = int.MaxValue,
        ILdapRequestTransport? schema = null)
    {
        // A bounded group must provide the sibling before the first search is
        // sent; never acquire it while holding the search lease.
        if (pageSize > 0 && ServerTimeLimit.TotalSeconds >= 1 && schema is null)
            throw new PlatformNotSupportedException("Buffered native paging with a finite server budget requires atomically admitted search and schema sessions.");
        if (request.Controls.Count != 0 || ConfigureConnectionOverride is not null)
            throw new PlatformNotSupportedException("The neutral producer cannot represent the requested control or connection policy.");
        var timeout = ClientTimeout >= TimeSpan.Zero ? ClientTimeout : transport.Timeout;
        TimeSpan Remaining()
        {
            origin.Authority.Validate();
            var remaining = timeout - clock.GetElapsedTime(started);
            return remaining > TimeSpan.Zero ? remaining : throw new TimeoutException("The neutral search operation deadline expired.");
        }
        var serverBudget = CreateServerTimeLimitBudget(pageSize > 0);
        TimeSpan? NextServerLimit() => serverBudget.TryApply(request) ? request.TimeLimit : null;
        var command = LdapRequestDispatcher.FromRequest(transport, request, Remaining());
        var session = lease.ManagedSession ?? throw new PlatformNotSupportedException("A neutral search requires an exclusive session.");
        var materialized = new List<SearchResult>();
        async Task<List<LdapTransportEntry>> Read()
        {
            var entries = new List<LdapTransportEntry>();
            await foreach (var item in LdapConversation.SearchBorrowed(session, command, pageSize,
                timeProvider: clock, remainingBudget: Remaining, nextServerLimit: NextServerLimit).ConfigureAwait(false))
            {
                if (item is LdapSearchEvent.Entry entry) entries.Add(entry.Value);
                else if (item is LdapSearchEvent.PageEnd end)
                {
                    if (end.Result.Code is not (ResultCode.Success or ResultCode.SizeLimitExceeded))
                        throw LdapExceptionTranslator.Translate(end.Result.Code, end.Result.Diagnostic ?? "LDAP search failed.");
                    if (schema is not null)
                    {
                        // Finish this accepted page while both sibling sessions
                        // remain alive. Advancing the iterator may retire the whole
                        // worker at server-budget exhaustion or cursor failure.
                        foreach (var value in entries)
                            materialized.Add(new SearchResult(value, origin, schema, Remaining));
                        entries.Clear();
                    }
                }
            }
            return entries;
        }
        try
        {
            // A single-session path waits for terminal cleanup before schema use;
            // the atomically admitted pair materializes each accepted page first.
            var entries = Read().GetAwaiter().GetResult();
            _ = Remaining(); // cleanup cannot publish rows after client deadline/authority expiry
            return schema is not null ? materialized.Take(maximumResults).ToArray() :
                entries.Take(maximumResults).Select(entry => new SearchResult(entry, origin, transport, Remaining)).ToArray();
        }
        catch { lease.Invalidate(); throw; }
    }

    // Capability-selected producer for the neutral backend. The default Protocols
    // producer retains its existing timing, partial-result and control behavior.
    private SearchResultCollection FindAllNeutralStreaming(DirectoryEntry root, SearchResultOrigin origin,
        DirectoryEntry.ConnectionLease[] leases, ILdapRequestTransport transport, SearchRequest request,
        TimeProvider clock, long started)
    {
        StreamingSearchResultSource? source = null;
        try
        {
            if (request.Controls.Count != 0 || ConfigureConnectionOverride is not null)
                throw new PlatformNotSupportedException("Public control-response state and connection overrides require an adapter that represents them.");
            var pageSize = PageSize;
            var partial = Asynchronous;
            var timeout = ClientTimeout >= TimeSpan.Zero ? ClientTimeout : transport.Timeout;
            TimeSpan Remaining()
            {
                origin.Authority.Validate();
                var remaining = timeout - clock.GetElapsedTime(started);
                return remaining > TimeSpan.Zero ? remaining : throw new TimeoutException("The neutral search operation deadline expired.");
            }
            var command = LdapRequestDispatcher.FromRequest(transport, request, Remaining());
            var required = LdapTransportCapabilities.StreamingSearch |
                (pageSize == 0 ? LdapTransportCapabilities.None : LdapTransportCapabilities.PagedSearch);
            if ((transport.Capabilities & required) != required || leases[0].ManagedSession is not { } searchSession)
                throw new PlatformNotSupportedException("The admitted transport cannot execute this streaming request.");
            var schema = leases[1].ExecuteTransport(value => value);
            source = new StreamingSearchResultSource((add, cancellationToken) =>
            {
                async Task Produce()
                {
                    var serverBudget = CreateServerTimeLimitBudget(pageSize > 0);
                    TimeSpan? NextServerLimit() => serverBudget.TryApply(request) ? request.TimeLimit : null;
                    var pending = new List<LdapTransportEntry>();
                    // Preserve existing public per-page duplicate suppression. Native
                    // MSG_ONE itself introduces no partial/final overlap.
                    var returnedDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    void Add(LdapTransportEntry entry)
                    {
                        if (!returnedDns.Add(entry.DistinguishedName)) return;
                        origin.Authority.Validate();
                        add(new SearchResult(entry, origin, schema, Remaining, cancellationToken));
                    }
                    await foreach (var item in LdapConversation.Search(() => searchSession,
                        command with { Timeout = Remaining() }, pageSize, cancellationToken, clock, Remaining, NextServerLimit).ConfigureAwait(false))
                    {
                        origin.Authority.Validate();
                        switch (item)
                        {
                            case LdapSearchEvent.Entry entry:
                                if (partial) Add(entry.Value); else pending.Add(entry.Value);
                                break;
                            case LdapSearchEvent.PageEnd end:
                                if (end.Result.Code is not (ResultCode.Success or ResultCode.SizeLimitExceeded))
                                    throw LdapExceptionTranslator.Translate(end.Result.Code, end.Result.Diagnostic ?? "LDAP search failed.");
                                foreach (var entry in pending) Add(entry);
                                pending.Clear(); returnedDns.Clear();
                                break;
                            // Returned references are not followed here; native policy
                            // was admitted before binding, just as in the Protocols path.
                            case LdapSearchEvent.Reference: break;
                        }
                    }
                }
                try { Produce().GetAwaiter().GetResult(); }
                catch { foreach (var lease in leases) lease.Invalidate(); throw; }
                finally
                {
                    foreach (var lease in leases) lease.Dispose();
                    root.Dispose();
                }
            });
            return new SearchResultCollection(source, CacheResults, GetPropertiesLoaded());
        }
        catch
        {
            if (source is not null) source.Dispose(); // producer owns cleanup now
            else
            {
                foreach (var lease in leases) { lease.Invalidate(); lease.Dispose(); }
                root.Dispose();
            }
            throw;
        }
    }
}
