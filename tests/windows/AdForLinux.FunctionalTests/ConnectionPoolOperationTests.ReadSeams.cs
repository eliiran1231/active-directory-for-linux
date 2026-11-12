using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class ReadSeamTransport(Func<LdapSearchCommand, LdapSearchResult> reply) : ILdapRequestTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls;
        public TimeSpan Timeout => TimeSpan.FromSeconds(5);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token) => reply(command);
        public void Dispose() => Disposals++;
    }

    [Fact]
    public void Borrowed_search_preserves_original_Protocols_request_metadata_and_response()
    {
        var request = new SearchRequest("CN=test", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, "description")
        { RequestId = "original", TimeLimit = TimeSpan.FromSeconds(2), Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Always };
        request.Controls.Add(new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl));
        using var connection = Connection.Create(sent =>
        {
            Assert.Same(request, sent);
            return Response("CN=test", new() { ["description"] = ["text"] });
        });
        using var lease = new Entry.ConnectionLease(connection);
        var response = lease.Search(request);
        Assert.Equal("text", Encoding.UTF8.GetString(response.Entries[0].Attributes["description"][0]));
        Assert.Equal(ResultCode.Success, response.Code);
    }

    [Fact]
    public void Borrowed_Protocols_binary_read_does_not_accept_a_string_as_security_bytes()
    {
        using var connection = Connection.Create(_ => Response("CN=test", new() { ["nTSecurityDescriptor"] = ["not binary"] }));
        using var entry = new Entry("LDAP://directory.invalid/CN=test");
        entry.SetControlledRetainedConnections(connection);
        Assert.Throws<InvalidOperationException>(() => entry.ReadSecurityDescriptorImmediate(AdForLinux.DirectoryServices.SecurityMasks.Dacl));
    }

    [Fact]
    public void Ranged_Protocols_read_keeps_original_timeout_and_schema_cache_identity()
    {
        var roots = 0; var ranges = 0;
        using var connection = Connection.Create(request =>
        {
            var search = Assert.IsType<SearchRequest>(request);
            if (search.Attributes.Contains("schemaNamingContext")) { roots++; return Response("", []); }
            ranges++;
            return ranges == 1
                ? Response("CN=test", new() { ["member;range=0-0"] = ["CN=a"] })
                : Response("CN=test", new() { ["member;range=1-*"] = ["CN=b"] });
        });
        connection.Timeout = TimeSpan.Zero; // existing Protocols contract permits zero
        using var entry = new Entry("LDAP://directory.invalid/CN=test");
        entry.SetControlledRetainedConnections(connection);
        Assert.Equal(new object[] { "CN=a", "CN=b" }, RangedAttributeReader.Read(entry, "member"));
        Assert.Equal(1, roots); Assert.Equal(2, ranges);
    }

    [Fact]
    public void Shared_read_seams_use_neutral_leases_for_schema_security_and_all_ranges()
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
        var transports = new List<ReadSeamTransport>();
        var requests = new List<(ReadSeamTransport Transport, LdapSearchCommand Command)>();
        LdapSearchResult Reply(LdapSearchCommand command)
        {
            Dictionary<string, byte[][]> attrs = new(StringComparer.OrdinalIgnoreCase);
            var dn = command.BaseDn;
            if (command.Attributes.Contains("schemaNamingContext")) attrs["schemaNamingContext"] = [Encoding.UTF8.GetBytes("CN=Schema")];
            else if (command.Filter.Contains("objectClass=classSchema")) dn = "CN=User,CN=Schema";
            else if (command.Filter.Contains("objectClass=attributeSchema")) { }
            else if (command.Attributes.Contains("member;range=0-*"))
            { attrs["member;range=0-*"] = []; attrs["member;range=0-1"] = [Encoding.UTF8.GetBytes("CN=a"), Encoding.UTF8.GetBytes("CN=b")]; }
            else if (command.Attributes.Contains("member;range=2-*")) attrs["member;range=2-*"] = [Encoding.UTF8.GetBytes("CN=c")];
            else if (command.Attributes.SequenceEqual(new[] { "nTSecurityDescriptor" }))
            { Assert.Equal(new byte[] { 0x30, 3, 2, 1, 4 }, Assert.Single(command.Controls!).Value); attrs["nTSecurityDescriptor"] = [[1, 0, 255]]; }
            else attrs["objectClass"] = [Encoding.UTF8.GetBytes("user")];
            return new(ResultCode.Success, "", null, [new(dn, attrs, [])], [], [], []);
        }
        using var entry = new Entry("LDAP://directory.invalid/CN=test", null, null, AuthenticationTypes.Secure);
        entry.OperationSessionFactory = (options, amount, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), amount, () =>
            {
                ReadSeamTransport? transport = null;
                transport = new(command => { requests.Add((transport!, command)); return Reply(command); });
                transports.Add(transport);
                return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
            }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        using var schema = entry.SchemaEntry;
        Assert.Equal("CN=User,CN=Schema", schema.DistinguishedName);
        Assert.Equal(new byte[] { 1, 0, 255 }, entry.ReadSecurityDescriptorImmediate(AdForLinux.DirectoryServices.SecurityMasks.Dacl));
        Assert.Equal(new object[] { "CN=a", "CN=b", "CN=c" }, RangedAttributeReader.Read(entry, "member"));
        var ranges = requests.Where(item => item.Command.Attributes.Any(name => name.StartsWith("member;range="))).ToArray();
        Assert.Equal(2, ranges.Length); Assert.Same(ranges[0].Transport, ranges[1].Transport);
        Assert.True(ranges[1].Command.Timeout <= ranges[0].Command.Timeout);
        Assert.All(transports, transport => Assert.Equal(1, transport.Disposals));
        Assert.Equal(0, pool.Snapshot.Total);
    }
}
