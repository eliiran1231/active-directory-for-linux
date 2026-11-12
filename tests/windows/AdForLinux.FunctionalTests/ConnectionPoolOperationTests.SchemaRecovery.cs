using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData(ResultCode.Unavailable)]
    [InlineData(ResultCode.ProtocolError)]
    [InlineData(ResultCode.InsufficientAccessRights)]
    public void Failed_schema_root_discovery_remains_retryable_on_same_resource(ResultCode failure)
    {
        using var transport = new RecordingTransport();
        var reject = true;
        var roots = 0;
        var queries = 0;
        transport.Reply = command =>
        {
            if (command.BaseDn == "")
            {
                roots++;
                return reject ? new(failure, "", "controlled root failure", [], [], [], [])
                    : new(ResultCode.Success, "", null,
                        [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], []);
            }
            queries++;
            return new(ResultCode.Success, "", null,
                [TransportRow("CN=flag,CN=Schema", new() { ["lDAPDisplayName"] = ["flag"],
                    ["attributeSyntax"] = ["2.5.5.8"], ["oMSyntax"] = ["1"] })], [], [], []);
        };

        var error = Assert.Throws<DirectoryServicesCOMException>(() => LdapAttributeSchema.Resolve(transport, ["flag"]));
        Assert.Equal((int)failure, error.ExtendedError);
        Assert.Equal(1, roots);
        Assert.Equal(0, queries);
        reject = false;
        Assert.Equal(LdapValueKind.Boolean, LdapAttributeSchema.Resolve(transport, ["flag"])["flag"]);
        Assert.Equal(LdapValueKind.Boolean, LdapAttributeSchema.Resolve(transport, ["FLAG;range=0-*"])["flag"]);
        Assert.Equal(2, roots);
        Assert.Equal(1, queries);
        Assert.Equal(3, transport.Sends);
    }

    [Theory]
    [InlineData(ResultCode.Unavailable)]
    [InlineData(ResultCode.ProtocolError)]
    public void Transient_schema_query_failure_does_not_cache_absent_syntax(ResultCode failure)
    {
        using var transport = new RecordingTransport();
        var queries = 0;
        transport.Reply = command => command.BaseDn == ""
            ? new(ResultCode.Success, "", null,
                [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], [])
            : ++queries == 1 ? new(failure, "", "controlled schema failure", [], [], [], [])
            : new(ResultCode.Success, "", null,
                [TransportRow("CN=count,CN=Schema", new() { ["lDAPDisplayName"] = ["count"],
                    ["attributeSyntax"] = ["2.5.5.16"], ["oMSyntax"] = ["65"] })], [], [], []);

        var error = Assert.Throws<DirectoryServicesCOMException>(() => LdapAttributeSchema.Resolve(transport, ["count"]));
        Assert.Equal((int)failure, error.ExtendedError);
        Assert.Equal(LdapValueKind.Int64, LdapAttributeSchema.Resolve(transport, ["count"])["count"]);
        Assert.Equal(LdapValueKind.Int64, LdapAttributeSchema.Resolve(transport, ["COUNT"])["count"]);
        Assert.Equal(2, queries);
        Assert.Equal(3, transport.Sends); // root is retained; the failed query is retried once
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Partial_schema_response_retains_found_types_but_requeries_missing_names(bool referral)
    {
        using var transport = new RecordingTransport();
        var queries = new List<LdapSearchCommand>();
        transport.Reply = command =>
        {
            if (command.BaseDn == "") return new(ResultCode.Success, "", null,
                [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], []);
            queries.Add(command);
            var first = queries.Count == 1;
            return new(ResultCode.Success, "", null,
                [TransportRow("CN=field,CN=Schema", new() { ["lDAPDisplayName"] = [first ? "flag" : "count"],
                    ["attributeSyntax"] = [first ? "2.5.5.8" : "2.5.5.9"], ["oMSyntax"] = [first ? "1" : "2"] })],
                first && !referral ? [new(["ldap://schema-reference.invalid/"], [])] : [],
                first && referral ? ["ldap://schema-referral.invalid/"] : [], []);
        };

        var partial = LdapAttributeSchema.Resolve(transport, ["flag", "count"]);
        Assert.Equal(LdapValueKind.Boolean, partial["flag"]);
        Assert.Equal(LdapValueKind.String, partial["count"]);
        Assert.Equal(2, transport.Sends);
        var complete = LdapAttributeSchema.Resolve(transport, ["FLAG", "COUNT"]);
        Assert.Equal(LdapValueKind.Boolean, complete["flag"]);
        Assert.Equal(LdapValueKind.Int32, complete["count"]);
        Assert.Equal(3, transport.Sends);
        Assert.Equal("(&(objectClass=attributeSchema)(lDAPDisplayName=COUNT))", queries[1].Filter);
        _ = LdapAttributeSchema.Resolve(transport, ["flag", "count"]);
        Assert.Equal(3, transport.Sends);
    }

    [Fact]
    public void Schema_lookup_canonicalizes_ranges_deduplicates_case_and_escapes_filter_values()
    {
        using var transport = new RecordingTransport();
        LdapSearchCommand? schemaRequest = null;
        transport.Reply = command =>
        {
            if (command.BaseDn == "") return new(ResultCode.Success, "", null,
                [TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] })], [], [], []);
            schemaRequest = command;
            return new(ResultCode.Success, "", null,
                [TransportRow("CN=field,CN=Schema", new() { ["lDAPDisplayName"] = ["FIELD"],
                    ["attributeSyntax"] = ["2.5.5.16"], ["oMSyntax"] = ["65"] })], [], [], []);
        };
        const string odd = "odd*)(name=*)\\\0";

        var resolved = LdapAttributeSchema.Resolve(transport, ["field;range=0-1", "FIELD", odd]);

        Assert.Equal(2, resolved.Count);
        Assert.Equal(LdapValueKind.Int64, resolved["field"]);
        Assert.Equal(LdapValueKind.String, resolved[odd]);
        Assert.NotNull(schemaRequest);
        Assert.Equal("(&(objectClass=attributeSchema)(|(lDAPDisplayName=field)(lDAPDisplayName=odd\\2a\\29\\28name=\\2a\\29\\5c\\00)))", schemaRequest.Filter);
        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, schemaRequest.Scope);
        Assert.Equal(new[] { "lDAPDisplayName", "attributeSyntax", "oMSyntax" }, schemaRequest.Attributes);
        Assert.Equal(LdapValueKind.Int64, LdapAttributeSchema.Resolve(transport, ["FiElD;range=2-*"])["field"]);
        Assert.Equal(2, transport.Sends);
    }
}
