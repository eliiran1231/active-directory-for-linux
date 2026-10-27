namespace AdForLinux.DirectoryServices.Ldap;

internal sealed class LdapWorkerResources(IDisposable owner, ILdapRequestTransport[] sessions) : IDisposable
{
    internal ILdapRequestTransport[] Sessions { get; } = sessions;
    public void Dispose() => owner.Dispose();
}
internal static class LdapWorkerHost
{
    internal static Task RunAsync(Stream channel, CancellationToken cancellationToken = default) =>
        RunAsync(channel, CreateProductionResources, cancellationToken);

    private static LdapWorkerResources CreateProductionResources(LdapWorkerStart profile)
    {
        LdapWorkerKerberosProfile.RequireProductionPolicy(profile);
        // The successful opt-in lab is not a deployment integrity attestation.
        // Never let optional protocol metadata or a caller flag activate binding.
        throw new PlatformNotSupportedException("Production isolated authentication composition is unavailable.");
    }

    internal static async Task RunAsync(Stream channel, Func<LdapWorkerStart, LdapWorkerResources> factory,
        CancellationToken cancellationToken = default)
    {
        LdapWorkerResources? resources = null;
        var cursors = new ILdapSearchCursor?[2];
        var ended = new bool[2]; var more = new bool[2]; var paged = new bool[2];
        long previous = 0;
        LdapWorkerFrame? request = null;
        async Task Reply<T>(string kind, T payload) => await LdapWorkerProtocol.WriteAsync(channel,
            LdapWorkerProtocol.Frame(request!.Id, request.Session, kind, TimeSpan.Zero, payload), cancellationToken).ConfigureAwait(false);
        try
        {
            request = await LdapWorkerProtocol.ReadAsync(channel, cancellationToken).ConfigureAwait(false);
            if (request.Id != 1 || request.Session != 0 || request.Kind != "START") throw new InvalidDataException("Expected worker start.");
            var profile = LdapWorkerProtocol.Payload<LdapWorkerStart>(request); LdapWorkerProtocol.ValidateStart(profile);
            if (request.TimeoutTicks <= 0 || request.TimeoutTicks > TimeSpan.FromHours(1).Ticks) throw new InvalidDataException("Invalid start budget.");
            LdapWorkerKerberosProfile.VerifyInherited(profile);
            resources = factory(profile);
            if (resources.Sessions.Length != profile.SessionCount || resources.Sessions.Any(value => value is null))
                throw new InvalidDataException("Factory returned invalid sessions.");
            await Reply("READY", new LdapWorkerReady(resources.Sessions.Select(value => value.Capabilities & ~LdapTransportCapabilities.ProtocolsConnection).ToArray())).ConfigureAwait(false);
            previous = request.Id;
            while (true)
            {
                request = await LdapWorkerProtocol.ReadAsync(channel, cancellationToken).ConfigureAwait(false);
                if (request.Id != checked(previous + 1) || request.Session >= resources.Sessions.Length ||
                    request.TimeoutTicks <= 0 || request.TimeoutTicks > TimeSpan.FromHours(1).Ticks)
                    throw new InvalidDataException("Invalid worker request sequence or budget.");
                previous = request.Id;
                var transport = resources.Sessions[request.Session];
                var remaining = TimeSpan.FromTicks(request.TimeoutTicks);
                var cursor = cursors[request.Session];
                switch (request.Kind)
                {
                    case "SEARCH":
                        Require(cursor is null);
                        var search = LdapWorkerProtocol.Payload<LdapSearchCommand>(request) with { Timeout = remaining };
                        await Reply("SEARCH_RESULT", LdapRequestDispatcher.Search(transport, search, cancellationToken)).ConfigureAwait(false);
                        break;
                    case "OPEN":
                        Require(cursor is null && transport is ILdapConversationTransport);
                        var open = LdapWorkerProtocol.Payload<LdapWorkerOpen>(request);
                        if (open.PageSize < 0) throw new InvalidDataException("Invalid page size.");
                        ended[request.Session] = false; more[request.Session] = false; paged[request.Session] = open.PageSize != 0;
                        cursors[request.Session] = await ((ILdapConversationTransport)transport).OpenSearchAsync(open.Command with { Timeout = remaining }, open.PageSize, cancellationToken).ConfigureAwait(false);
                        await Reply<object?>("OK", null).ConfigureAwait(false); break;
                    case "READ":
                        RequireNull(request); Require(cursor is not null && !ended[request.Session]);
                        var item = await cursor!.ReadAsync(remaining, cancellationToken).ConfigureAwait(false);
                        switch (item)
                        {
                            case LdapSearchEvent.Entry entry: await Reply("ENTRY", entry.Value).ConfigureAwait(false); break;
                            case LdapSearchEvent.Reference reference: await Reply("REFERENCE", reference.Value).ConfigureAwait(false); break;
                            case LdapSearchEvent.PageEnd page:
                                Require(!page.HasMore || paged[request.Session]);
                                ended[request.Session] = true; more[request.Session] = page.HasMore && page.Result.Code == System.DirectoryServices.Protocols.ResultCode.Success;
                                await Reply("PAGE", page).ConfigureAwait(false); break;
                            default: throw new InvalidDataException("Invalid cursor event.");
                        }
                        break;
                    case "NEXT":
                        RequireNull(request); Require(cursor is not null && ended[request.Session] && more[request.Session]);
                        ended[request.Session] = false;
                        await cursor!.NextPageAsync(remaining, cancellationToken).ConfigureAwait(false);
                        await Reply<object?>("OK", null).ConfigureAwait(false); break;
                    case "CLOSE":
                        RequireNull(request); Require(cursor is not null);
                        await cursor!.DisposeAsync().ConfigureAwait(false); cursors[request.Session] = null;
                        await Reply<object?>("OK", null).ConfigureAwait(false); break;
                    case "MODIFY": case "ADD": case "DELETE": case "RENAME":
                        Require(cursor is null);
                        LdapMutationCommand mutation = request.Kind switch
                        {
                            "MODIFY" => LdapWorkerProtocol.Payload<LdapModifyCommand>(request),
                            "ADD" => LdapWorkerProtocol.Payload<LdapAddCommand>(request),
                            "DELETE" => LdapWorkerProtocol.Payload<LdapDeleteCommand>(request),
                            _ => LdapWorkerProtocol.Payload<LdapModifyDnCommand>(request)
                        };
                        mutation = LdapMutationCommands.Prepare(mutation with { Timeout = remaining });
                        LdapMutationCommands.RequireCapabilities(transport, mutation);
                        var submission = new LdapSubmission(() =>
                        {
                            Reply<object?>("PREPARED", null).GetAwaiter().GetResult();
                            var go = LdapWorkerProtocol.ReadAsync(channel, cancellationToken).AsTask().GetAwaiter().GetResult();
                            if (go.Id != request.Id || go.Session != request.Session || go.Kind != "GO" || go.TimeoutTicks != 0)
                                throw new InvalidDataException("Invalid worker submission receipt.");
                            RequireNull(go);
                        });
                        var result = await LdapMutationCommands.SendAsync(transport, mutation, submission, cancellationToken).ConfigureAwait(false);
                        Require(submission.Started);
                        await Reply("WRITE_RESULT", result).ConfigureAwait(false); break;
                    default: throw new InvalidDataException("Unknown worker request.");
                }
            }
        }
        catch (Exception error)
        {
            if (request is not null)
                try { await Reply("ERROR", new LdapWorkerFailure(error is PlatformNotSupportedException ? "unsupported" : error is NativeLdapBindingBackend.NativeFailureException native && native.Status is >= 2 and <= 13 ? "native-" + native.Status.ToString(System.Globalization.CultureInfo.InvariantCulture) : error is System.Runtime.InteropServices.MarshalDirectiveException ? "marshal" : error is DllNotFoundException ? "library" : error is InvalidDataException ? "data" : error is ArgumentException ? "argument" : error is InvalidOperationException ? "state" : "failed")).ConfigureAwait(false); }
                catch { /* parent may already have closed the channel */ }
        }
        finally
        {
            // This cleanup runs only inside the disposable helper. A blocked
            // native close cannot hold up the parent after its deadline.
            foreach (var cursor in cursors)
                if (cursor is not null)
                    try { await cursor.DisposeAsync().ConfigureAwait(false); } catch { /* still attempt remaining resources */ }
            try { resources?.Dispose(); } catch { /* helper exit owns final cleanup */ }
        }
    }
    private static void Require(bool condition)
    { if (!condition) throw new InvalidDataException("Invalid worker session state."); }
    private static void RequireNull(LdapWorkerFrame frame) => Require(frame.Payload.ValueKind == System.Text.Json.JsonValueKind.Null);
}
