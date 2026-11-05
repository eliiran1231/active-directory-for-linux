using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private static readonly (string Name, string Syntax, string Om)[] MaterializationSchema =
    [ ("flag", "2.5.5.8", "1"), ("count", "2.5.5.9", "2"), ("large", "2.5.5.16", "65"),
      ("when", "2.5.5.11", "24"), ("blob", "2.5.5.10", "4"), ("members", "2.5.5.1", "127") ];
    private static LdapTransportEntry TransportRow(string dn, Dictionary<string, object[]> values) => new(dn,
        values.ToDictionary(pair => pair.Key, pair => pair.Value.Select(v => v is byte[] bytes ? bytes.ToArray() : Encoding.UTF8.GetBytes((string)v)).ToArray(),
            StringComparer.OrdinalIgnoreCase), []);

    [Fact]
    public void Neutral_result_materialization_matches_protocols_without_retaining_schema_transport()
    {
        using var root = new Entry("LDAP://directory.invalid/DC=example", "reader", "synthetic password", AuthenticationTypes.None);
        var origin = new SearchResultOrigin(root, root.CaptureBindingAuthority());
        var values = new Dictionary<string, object[]>
        {
            ["flag"] = ["TRUE"], ["count"] = ["42"], ["large"] = ["9223372036854775806"],
            ["when"] = ["20261025120000.0Z"], ["blob"] = [new byte[] { 0, 255, 65 }],
            ["unknown"] = [new byte[] { 255, 65 }], ["members;range=0-1"] = ["CN=a", "CN=b"], ["empty"] = []
        };
        var rows = MaterializationSchema.Select(row => new Dictionary<string, object[]>
        { ["lDAPDisplayName"] = [row.Name], ["attributeSyntax"] = [row.Syntax], ["oMSyntax"] = [row.Om] }).ToArray();
        using var connection = Connection.Create(request =>
        {
            var search = Assert.IsType<SearchRequest>(request);
            if (search.DistinguishedName == "") return Response("", new() { ["schemaNamingContext"] = ["CN=Schema"] });
            var response = Response("CN=attribute", rows[0]);
            foreach (var row in rows.Skip(1))
                typeof(SearchResultEntryCollection).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(response.Entries, [Response("CN=attribute", row).Entries[0]]);
            return response;
        });
        var expected = new SearchResult(Response("CN=first", values).Entries[0], origin, root, connection);
        using var transport = new RecordingTransport();
        transport.Reply = command => new(ResultCode.Success, "", null,
            command.BaseDn == "" ? [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })]
                : rows.Select(row => TransportRow("CN=attribute", row)).ToArray(), [], [], []);
        var raw = TransportRow("CN=first", values);
        var actual = new SearchResult(raw, origin, transport);
        Assert.Equal(expected.Path, actual.Path);
        foreach (string name in expected.Properties.PropertyNames)
        {
            var before = expected.Properties[name].Cast<object>().ToArray();
            var after = actual.Properties[name].Cast<object>().ToArray();
            Assert.Equal(before.Length, after.Length);
            for (var i = 0; i < before.Length; i++)
            {
                Assert.Equal(before[i].GetType(), after[i].GetType());
                if (before[i] is byte[] bytes) Assert.Equal(bytes, Assert.IsType<byte[]>(after[i]));
                else Assert.Equal(before[i], after[i]);
            }
        }
        Assert.Empty(actual.Properties["empty"].Cast<object>());
        Assert.Equal(2, transport.Sends);
        _ = new SearchResult(raw, origin, transport);
        Assert.Equal(2, transport.Sends); // schema cache belongs to this resource
        raw.Attributes["blob"][0][0] = 99;
        Assert.Equal(0, ((byte[])actual.Properties["blob"][0])[0]);
        transport.Dispose();
        using var reopenedRecipe = actual.GetDirectoryEntry();
        Assert.Equal(actual.Path, reopenedRecipe.Path); // no borrowed schema access after materialization
    }

    [Fact]
    public void Neutral_schema_cache_is_resource_scoped_and_preserves_failure_boundaries()
    {
        using var first = new RecordingTransport(); using var second = new RecordingTransport();
        first.Reply = command => new(ResultCode.Success, "", null, command.BaseDn == ""
            ? [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })]
            : [TransportRow("CN=attribute", new() { ["lDAPDisplayName"] = ["count"], ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] })], [], [], []);
        second.Reply = _ => new(ResultCode.Success, "", null, [], [], [], []);
        Assert.Equal(LdapValueKind.Int32, LdapAttributeSchema.Resolve(first, ["count"])["count"]);
        Assert.Equal(LdapValueKind.String, LdapAttributeSchema.Resolve(second, ["count"])["count"]);
        Assert.Equal(LdapValueKind.Binary, LdapAttributeSchema.Resolve(second, ["objectGUID"])["objectGUID"]);
        Assert.Equal(1, second.Sends);
        using var rootFailure = new RecordingTransport { Reply = _ => new(ResultCode.InsufficientAccessRights, "", "denied", [], [], [], []) };
        Assert.Throws<DirectoryServicesCOMException>(() => LdapAttributeSchema.Resolve(rootFailure, ["count"]));
        using var queryFailure = new RecordingTransport();
        queryFailure.Reply = command => command.BaseDn == ""
            ? new(ResultCode.Success, "", null, [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], [])
            : new(ResultCode.NoSuchObject, "", "no AD schema", [], [], [], []);
        Assert.Equal(LdapValueKind.Binary, LdapAttributeSchema.Resolve(queryFailure, ["objectGUID"])["objectGUID"]);
        using var broken = new RecordingTransport { Reply = _ => throw new InvalidOperationException("transport unavailable") };
        Assert.Throws<InvalidOperationException>(() => LdapAttributeSchema.Resolve(broken, ["count"]));
    }
    [Fact]
    public void Neutral_schema_budget_and_incomplete_result_do_not_reset_or_poison_cache()
    {
        using var transport = new RecordingTransport();
        var budgets = new List<TimeSpan>(); var left = TimeSpan.FromSeconds(1); var schemaQueries = 0;
        transport.Reply = command =>
        {
            budgets.Add(command.Timeout);
            if (command.BaseDn == "")
            {
                left = TimeSpan.FromMilliseconds(250);
                return new(ResultCode.Success, "", null, [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], []);
            }
            if (++schemaQueries == 1) return new(ResultCode.Success, "", null, [], [new(["ldap://reference.invalid/"], [])], [], []);
            return new(ResultCode.Success, "", null,
                [TransportRow("CN=count", new() { ["lDAPDisplayName"] = ["count"], ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] })], [], [], []);
        };
        Assert.Equal(LdapValueKind.String, LdapAttributeSchema.Resolve(transport, ["count"], () => left)["count"]);
        Assert.Equal(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(250) }, budgets);
        Assert.Equal(LdapValueKind.Int32, LdapAttributeSchema.Resolve(transport, ["count"], () => left)["count"]);
        Assert.Equal(3, transport.Sends);
        Assert.Throws<TimeoutException>(() => LdapAttributeSchema.Resolve(transport, ["count"], () => TimeSpan.Zero));
        Assert.Equal(3, transport.Sends);
        using var lateRoot = new RecordingTransport();
        var rootBudget = TimeSpan.FromSeconds(1);
        lateRoot.Reply = _ => { rootBudget = TimeSpan.Zero; return new(ResultCode.Success, "", null, [], [], [], []); };
        Assert.Throws<TimeoutException>(() => LdapAttributeSchema.Resolve(lateRoot, ["empty"], () => rootBudget));
        using var expired = new RecordingTransport();
        Assert.Throws<TimeoutException>(() => LdapAttributeSchema.Resolve(expired, ["count"], () => TimeSpan.Zero));
        Assert.Equal(0, expired.Sends);
        using var unavailable = new RecordingTransport();
        unavailable.Reply = command => command.BaseDn == ""
            ? new(ResultCode.Success, "", null, [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], [])
            : new(ResultCode.Unavailable, "", "connection lost", [], [], [], []);
        Assert.Throws<DirectoryServicesCOMException>(() => LdapAttributeSchema.Resolve(unavailable, ["count"]));
    }

}
