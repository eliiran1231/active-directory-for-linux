using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;
using Context = AdForLinux.DirectoryServices.AccountManagement.PrincipalContext;
using ContextType = AdForLinux.DirectoryServices.AccountManagement.ContextType;
using ContextOptions = AdForLinux.DirectoryServices.AccountManagement.ContextOptions;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class RecordingTransport : ILdapRequestTransport, IDisposable
    {
        internal int Sends, Disposals;
        internal LdapSearchCommand? Last;
        internal Func<LdapSearchCommand, LdapSearchResult>? Reply;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search;
        public TimeSpan Timeout => TimeSpan.FromSeconds(5);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
        {
            Sends++; Last = command;
            if (Reply is not null) return Reply(command);
            var values = command.Attributes.ToDictionary(a => a, a => new[] { Encoding.UTF8.GetBytes(
                a == "dnsHostName" ? "observed-dc.invalid" : "DC=example") }, StringComparer.OrdinalIgnoreCase);
            return new(ResultCode.Success, "", null, [new("", values, [])], [], [], []);
        }
        public void Dispose() => Disposals++;
    }

    [Fact]
    public void Both_public_facades_discover_through_the_same_neutral_lease_without_protocols_handles()
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        var transports = new List<RecordingTransport>();
        LdapConnectionProvider.Session[] Open(LdapConnectionOptions options, int count, ReferralChasingOption referrals, bool fresh, long minimum)
            => pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
            {
                var transport = new RecordingTransport(); transports.Add(transport);
                return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
            }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        using var entry = new Entry("LDAP://directory.invalid/DC=example", null, null, AuthenticationTypes.Secure);
        entry.Options.Referral = ReferralChasingOption.None; entry.OperationSessionFactory = Open;
        Assert.Equal("observed-dc.invalid", entry.Options.GetCurrentServerName());
        using var context = new Context(ContextType.Domain, "directory.invalid", null, ContextOptions.Negotiate);
        context.TransportSessionFactory = options => Open(options, 1, ReferralChasingOption.None, false, 0)[0];
        Assert.Equal("observed-dc.invalid", context.ConnectedServer);
        Assert.Equal("DC=example", context.DefaultNamingContext);
        Assert.Equal(3, transports.Count);
        Assert.All(transports, transport =>
        {
            Assert.Equal(1, transport.Sends); Assert.Equal(1, transport.Disposals);
            Assert.Equal(ProtocolScope.Base, transport.Last!.Scope);
            Assert.Equal("", transport.Last.BaseDn);
        });
        using var session = Open(entry.BuildOptions(), 1, ReferralChasingOption.None, false, 0)[0];
        Assert.Throws<PlatformNotSupportedException>(() => session.Connection);
    }

    [Fact]
    public void Request_capabilities_cancellation_and_nul_are_checked_before_dispatch()
    {
        using var transport = new RecordingTransport();
        var command = new LdapSearchCommand("", "(objectClass=*)", ProtocolScope.Base, ["dnsHostName"], transport.Timeout);
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.Search(transport,
            command with { Controls = [new("1.2.3", [], true)] }));
        Assert.Throws<ArgumentException>(() => LdapRequestDispatcher.Search(transport, command with { Filter = "(a=\0b)" }));
        Assert.Throws<OperationCanceledException>(() => LdapRequestDispatcher.Search(transport, command, new CancellationToken(true)));
        Assert.Equal(0, transport.Sends);
        LdapRequestDispatcher.Search(transport, command with { Timeout = TimeSpan.FromHours(2) });
        Assert.Equal(1, transport.Sends); // native timeout ceiling is not a neutral/Protocols rule
    }

    [Fact]
    public void Root_discovery_translates_failure_and_does_not_invent_connected_host()
    {
        using var transport = new RecordingTransport();
        var entry = new LdapTransportEntry("", new(StringComparer.OrdinalIgnoreCase)
        { ["dnsHostName"] = [Encoding.UTF8.GetBytes("partial.invalid")] }, []);
        transport.Reply = _ => new(ResultCode.SizeLimitExceeded, "", "partial", [entry], [], [], []);
        Assert.Throws<DirectoryServicesCOMException>(() => RootDse.GetConnectedServerName(transport));
        transport.Reply = _ => new(ResultCode.Success, "", null, [], [], [], []);
        Assert.Throws<InvalidOperationException>(() => RootDse.GetConnectedServerName(transport));
        Assert.Equal(2, transport.Sends);
    }

    [Fact]
    public void Protocols_root_discovery_preserves_first_entry_with_successful_references_and_referrals()
    {
        const System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var response = (SearchResponse)Activator.CreateInstance(typeof(SearchResponse), flags, null,
            new object?[] { null, Array.Empty<DirectoryControl>(), ResultCode.Success, null,
                new[] { new Uri("ldap://never-follow.invalid/") } }, null)!;
        foreach (var host in new[] { "first.invalid", "second.invalid" })
        {
            var entry = Response("", new() { ["dnsHostName"] = [host] }).Entries[0];
            typeof(SearchResultEntryCollection).GetMethod("Add", flags)!.Invoke(response.Entries, [entry]);
        }
        var reference = (SearchResultReference)Activator.CreateInstance(typeof(SearchResultReference), flags, null,
            new object[] { new[] { new Uri("ldap://never-follow.invalid/") } }, null)!;
        typeof(SearchResultReferenceCollection).GetMethod("Add", flags)!.Invoke(response.References, [reference]);
        var sends = 0;
        using var connection = Connection.Create(_ => { sends++; return response; });
        Assert.Equal("first.invalid", RootDse.GetConnectedServerName(connection));
        Assert.Equal(1, sends);
    }

    [Fact]
    public void Native_stream_message_parser_preserves_kind_and_requires_complete_owned_payload()
    {
        var entry = new NativeSearchResultBuilder();
        entry.Accept(1, "CN=first", [], 0); entry.Accept(6, null, [], 0);
        Assert.Equal("CN=first", Assert.IsType<LdapSearchEvent.Entry>(entry.CompleteEvent(1, false)).Value.DistinguishedName);
        Assert.Throws<InvalidOperationException>(() => entry.CompleteEvent(3, false));
        Assert.Throws<InvalidOperationException>(() => entry.CompleteEvent(1, true));
        var reference = new NativeSearchResultBuilder();
        reference.Accept(7, null, [], 0); reference.Accept(8, "ldap://returned.invalid/", [], 0); reference.Accept(10, null, [], 0);
        Assert.Single(Assert.IsType<LdapSearchEvent.Reference>(reference.CompleteEvent(2, false)).Value.Urls);
        var result = new NativeSearchResultBuilder();
        result.Accept(11, null, [], (int)ResultCode.SizeLimitExceeded);
        result.Accept(13, "partial result", [], 0);
        var page = Assert.IsType<LdapSearchEvent.PageEnd>(result.CompleteEvent(3, false));
        Assert.Equal(ResultCode.SizeLimitExceeded, page.Result.Code);
        Assert.Equal("partial result", page.Result.Diagnostic);
        Assert.Throws<InvalidOperationException>(() => new NativeSearchResultBuilder().CompleteEvent(3, false));
    }

    [Fact]
    public void Native_result_copy_survives_native_buffer_release_and_preserves_full_search_envelope()
    {
        var memory = Marshal.AllocHGlobal(3);
        byte[] bytes;
        try
        {
            Marshal.Copy(new byte[] { 0, 255, 65 }, 0, memory, 3);
            bytes = NativeLdapBindingBackend.BoundSession.Copy(memory, (UIntPtr)3);
        }
        finally { Marshal.FreeHGlobal(memory); }
        var builder = new NativeSearchResultBuilder();
        builder.Accept(1, "CN=example", [], 0);
        builder.Accept(2, "binary", [], 0); builder.Accept(3, null, bytes, 0); builder.Accept(4, null, [], 0);
        builder.Accept(5, "1.2.3", bytes, 3); builder.Accept(6, null, [], 0);
        builder.Accept(7, null, [], 0); builder.Accept(8, "ldap://reference.invalid/", [], 0);
        builder.Accept(9, "1.2.4", [], 0); builder.Accept(10, null, [], 0);
        builder.Accept(11, null, [], (int)ResultCode.SizeLimitExceeded);
        builder.Accept(12, "DC=example", [], 0); builder.Accept(13, "limit", [], 0);
        builder.Accept(14, "ldap://referral.invalid/", [], 0); builder.Accept(15, "1.2.5", bytes, 2);
        var result = builder.Complete();
        Assert.Equal(ResultCode.SizeLimitExceeded, result.Code);
        Assert.Equal(new byte[] { 0, 255, 65 }, result.Entries[0].Attributes["binary"][0]);
        Assert.True(result.Entries[0].Controls[0].Critical);
        Assert.Single(result.References); Assert.Single(result.Referrals); Assert.Single(result.Controls);
        Assert.Equal("DC=example", result.MatchedDn); Assert.Equal("limit", result.Diagnostic);
        Assert.Throws<InvalidOperationException>(() => builder.Accept(1, "late", [], 0));
        Assert.Throws<InvalidOperationException>(() => new NativeSearchResultBuilder().Complete());
        Assert.Throws<InvalidOperationException>(() => new NativeSearchResultBuilder().Accept(6, null, [], 0));
    }

    [Fact]
    public void Protocols_adapter_preserves_binary_values_and_uses_existing_request_exception_seam()
    {
        using var connection = Connection.Create(request =>
        {
            var search = Assert.IsType<SearchRequest>(request);
            Assert.Equal(TimeSpan.Zero, search.TimeLimit);
            return Response("", new() { ["binary"] = [new byte[] { 0, 255, 65 }] });
        });
        var transport = new ProtocolsLdapTransport(connection);
        var result = LdapRequestDispatcher.Search(transport,
            new LdapSearchCommand("", "(objectClass=*)", ProtocolScope.Base, ["binary"], transport.Timeout));
        Assert.Equal(new byte[] { 0, 255, 65 }, result.Entries[0].Attributes["binary"][0]);
    }
}
