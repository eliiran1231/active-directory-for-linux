using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using Searcher = AdForLinux.DirectoryServices.DirectorySearcher;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class FailureEnvelopeTransport(LdapResultEnvelope envelope, List<LdapSearchCommand> requests)
        : ILdapConversationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Reads, CursorDisposals, Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.StreamingSearch;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            requests.Add(command);
            Assert.Equal(new[] { "1.1" }, command.Attributes);
            return new(ResultCode.Success, "", null, [new(command.BaseDn, new(), [])], [], [], []);
        }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(0, pageSize);
            requests.Add(command);
            return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal(0, Reads++);
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(envelope, false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("An unpaged rejected search cannot advance.");
        public ValueTask DisposeAsync() { CursorDisposals++; return ValueTask.CompletedTask; }
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Read-only failure comparison attempted a mutation.");
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_search_failure_preserves_extended_error_but_neutral_inner_exception_has_no_response(bool findAll)
    {
        const string dn = "DC=example,DC=test", diagnostic = "controlled access rejection";
        const string referral = "ldap://never-follow.invalid/DC=other";
        var envelope = new LdapResultEnvelope(ResultCode.InsufficientAccessRights, dn, diagnostic,
            [referral], [new("1.2.3.4", [0, 255], true)]);
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var response = (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
            new object?[] { dn, new[] { new DirectoryControl("1.2.3.4", [0, 255], true, true) },
                envelope.Code, diagnostic, new[] { new Uri(referral) } }, null)!;
        var original = new DirectoryOperationException(response, "controlled operation failure");

        DirectoryServicesCOMException Exercise(bool neutral)
        {
            using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
            using var root = new Entry("LDAP://offline.invalid/" + dn);
            root.Options.Referral = ReferralChasingOption.None;
            var requests = new List<LdapSearchCommand>();
            var transports = new List<FailureEnvelopeTransport>();
            var connections = new List<Connection>();
            root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    if (neutral)
                    {
                        var transport = new FailureEnvelopeTransport(envelope, requests);
                        transports.Add(transport);
                        return new BoundLdapSession(transport, transport, options, new(options), referrals);
                    }
                    var connection = Connection.Create(request =>
                    {
                        var search = Assert.IsType<SearchRequest>(request);
                        requests.Add(new(search.DistinguishedName, Assert.IsType<string>(search.Filter), search.Scope,
                            search.Attributes.Cast<string>().ToArray(), TimeSpan.FromSeconds(10), search.SizeLimit));
                        if (search.Attributes.Contains("1.1")) return Response(dn, new());
                        throw original;
                    });
                    connections.Add(connection);
                    return new BoundLdapSession(connection, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            using var searcher = new Searcher(root) { ReferralChasing = ReferralChasingOption.None };
            searcher.PropertiesToLoad.Add("description");
            // Only the synthetic Protocols path bypasses platform configuration;
            // its uninitialized connection must never touch a native handle.
            if (!neutral) searcher.ConfigureConnectionOverride = _ => { };
            var error = Assert.Throws<DirectoryServicesCOMException>(() =>
            {
                if (findAll) { using var results = searcher.FindAll(); _ = results.Count; }
                else _ = searcher.FindOne();
            });
            Assert.Equal(2, requests.Count);
            Assert.All(requests, request => Assert.Equal(dn, request.BaseDn));
            Assert.Equal(new[] { "1.1" }, requests[0].Attributes);
            Assert.Equal(new[] { "description", "ADsPath" }, requests[1].Attributes);
            Assert.Equal(findAll ? 0 : 1, requests[1].SizeLimit);
            Assert.Equal(0, pool.Snapshot.Total);
            Assert.Equal(0, pool.Snapshot.Waiting);
            if (neutral)
            {
                Assert.Equal(2, transports.Count);
                Assert.All(transports, transport => Assert.Equal(1, transport.Disposals));
                Assert.Equal(1, transports.Sum(transport => transport.Reads));
                Assert.Equal(1, transports.Sum(transport => transport.CursorDisposals));
            }
            else
            {
                Assert.Equal(2, connections.Count);
                Assert.All(connections, connection => Assert.Equal(1, connection.Disposals));
            }
            return error;
        }

        var protocolsError = Exercise(neutral: false);
        var neutralError = Exercise(neutral: true);
        Assert.Equal(unchecked((int)0x80070005), protocolsError.HResult);
        Assert.Equal(protocolsError.HResult, neutralError.HResult);
        Assert.Equal((int)envelope.Code, protocolsError.ExtendedError);
        Assert.Equal(protocolsError.ExtendedError, neutralError.ExtendedError);
        Assert.Equal(diagnostic, protocolsError.ExtendedErrorMessage);
        Assert.Equal(diagnostic, neutralError.ExtendedErrorMessage);
        Assert.Contains(diagnostic, protocolsError.Message);
        Assert.Equal(diagnostic, neutralError.Message);
        Assert.Same(original, Assert.IsType<DirectoryOperationException>(protocolsError.InnerException));
        var preserved = Assert.IsType<SearchResponse>(original.Response);
        Assert.Same(response, preserved);
        Assert.Equal(envelope.Code, preserved.ResultCode);
        Assert.Equal(envelope.MatchedDn, preserved.MatchedDN);
        Assert.Equal(envelope.Diagnostic, preserved.ErrorMessage);
        Assert.Equal(referral, Assert.Single(preserved.Referral).AbsoluteUri);
        var control = Assert.Single(preserved.Controls);
        Assert.Equal(envelope.Controls[0].Oid, control.Type);
        Assert.Equal(envelope.Controls[0].Critical, control.IsCritical);
        Assert.Equal(envelope.Controls[0].Value, control.GetValue());
        Assert.Null(Assert.IsType<DirectoryOperationException>(neutralError.InnerException).Response);
        // Characterizes a backend parity limit. No Microsoft behavioral oracle
        // establishes that a nested Protocols response is part of the contract.
    }
}
