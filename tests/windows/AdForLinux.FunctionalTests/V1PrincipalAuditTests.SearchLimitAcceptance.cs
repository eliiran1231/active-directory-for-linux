using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    // The existing live differential case is the Microsoft oracle for early
    // native failure (#203). These recording tests distinguish that stage from
    // eager schema/conversion and principal attachment; no AD is contacted.
    [Theory]
    [InlineData("schema", false)]
    [InlineData("conversion", false)]
    [InlineData("principal", false)]
    [InlineData("schema", true)]
    [InlineData("conversion", true)]
    [InlineData("principal", true)]
    public void FindOne_restores_limit_before_accepted_result_materialization_failure(string stage, bool partial)
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principals = new PrincipalSearcher(query);
        var native = Assert.IsType<DirectorySearcher>(principals.GetUnderlyingSearcher());
        native.PageSize = 0;
        native.ReferralChasing = ReferralChasingOption.None;
        native.ConfigureConnectionOverride = _ => { };
        native.SizeLimit = 7;
        var failure = new InvalidOperationException("controlled late materialization failure");
        const string rowDn = "CN=found,DC=example,DC=test";
        const string schemaDn = "CN=Schema,CN=Configuration,DC=example,DC=test";
        fixture.Reply = number =>
        {
            var request = fixture.Queries[^1];
            if (number == 1)
            {
                Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Subtree, request.Scope);
                Assert.Equal(1, request.SizeLimit);
                var response = SaveResponse(rowDn, stage == "principal" ? [] :
                    new() { ["customInteger"] = ["not-an-integer"] }, 1,
                    partial ? ResultCode.SizeLimitExceeded : ResultCode.Success, false, false);
                if (partial) throw new DirectoryOperationException(response);
                return response;
            }
            // The caller limit must already be restored when the first schema
            // or principal-entry read starts, not merely after unwinding.
            Assert.Equal(7, native.SizeLimit);
            if (stage == "principal")
            {
                Assert.Equal(rowDn, request.DistinguishedName);
                Assert.Equal(new[] { "*", "nTSecurityDescriptor" }, request.Attributes.Cast<string>());
                throw failure;
            }
            if (request.DistinguishedName == "")
            {
                Assert.Contains("schemaNamingContext", request.Attributes.Cast<string>());
                if (stage == "schema") throw failure;
                return SaveResponse("", new() { ["schemaNamingContext"] = [schemaDn] }, 1, ResultCode.Success, false, false);
            }
            Assert.Equal(schemaDn, request.DistinguishedName);
            Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, request.Scope);
            return SaveResponse("CN=customInteger," + schemaDn, new()
            {
                ["lDAPDisplayName"] = ["customInteger"], ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"],
            }, 1, ResultCode.Success, false, false);
        };

        var error = Record.Exception(() => principals.FindOne());
        if (stage == "conversion") Assert.IsType<FormatException>(error);
        else Assert.Same(failure, error);
        Assert.Equal(7, native.SizeLimit);
        Assert.Equal(stage == "conversion" ? 3 : 2, fixture.Queries.Count);
        fixture.AssertReleased();

        fixture.Queries.Clear();
        fixture.Reply = _ => EmptyProtocolScopeResponse();
        using var recovered = principals.FindAll();
        Assert.Empty(recovered);
        Assert.Equal(7, Assert.Single(fixture.Queries).SizeLimit);
        fixture.AssertReleased();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    public void Failed_FindAll_keeps_caller_limit_without_a_FindOne_temporary_override(int originalLimit)
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principals = new PrincipalSearcher(query);
        var native = Assert.IsType<DirectorySearcher>(principals.GetUnderlyingSearcher());
        native.PageSize = 0;
        native.ReferralChasing = ReferralChasingOption.None;
        native.ConfigureConnectionOverride = _ => { };
        native.SizeLimit = originalLimit;
        var response = SaveResponse("", [], 0, ResultCode.NoSuchObject, false, false);
        fixture.Reply = _ => throw new DirectoryOperationException(response);

        var error = Assert.Throws<PrincipalOperationException>(() => principals.FindAll());
        Assert.Equal(unchecked((int)0x80072030), error.ErrorCode);
        Assert.Equal(originalLimit, native.SizeLimit);
        Assert.Equal(originalLimit, Assert.Single(fixture.Queries).SizeLimit);
        fixture.AssertReleased();
    }

    [Fact]
    public void FindOne_acquisition_failure_keeps_temporary_limit_without_dispatch()
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principals = new PrincipalSearcher(query);
        var native = Assert.IsType<DirectorySearcher>(principals.GetUnderlyingSearcher());
        native.SizeLimit = 7;
        var failure = new InvalidOperationException("controlled acquisition failure");
        fixture.Context.SearchRoot.OperationSessionFactory = (_, _, _, _, _) => throw failure;

        Assert.Same(failure, Record.Exception(() => principals.FindOne()));
        Assert.Equal(1, native.SizeLimit);
        Assert.Empty(fixture.Queries);
        Assert.Equal(0, fixture.RootReads);
        Assert.Equal(0, fixture.Pool.Snapshot.Total);
        Assert.Equal(0, fixture.Pool.Snapshot.Waiting);
    }

    [Fact]
    public void Direct_DirectorySearcher_FindOne_failure_preserves_its_own_public_limit()
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var native = new DirectorySearcher(fixture.Context.SearchRoot)
        {
            SizeLimit = 7, ReferralChasing = ReferralChasingOption.None, ConfigureConnectionOverride = _ => { },
        };
        var failure = new InvalidOperationException("controlled native query failure");
        fixture.Reply = _ => throw failure;

        Assert.Same(failure, Record.Exception(() => native.FindOne()));
        Assert.Equal(7, native.SizeLimit);
        Assert.Equal(1, Assert.Single(fixture.Queries).SizeLimit);
        fixture.AssertReleased();
    }

    [Theory]
    [InlineData("native-failure", 1, 3)]
    [InlineData("fallback-empty", 7, 4)]
    [InlineData("fallback-list-failure", 1, 4)]
    [InlineData("fallback-row-failure", 7, 5)]
    public void Attribute_scoped_FindOne_restores_only_after_native_or_reference_list_acceptance(string mode, int expectedLimit, int requests)
    {
        using var fixture = new ProtocolFailureScopeFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var principals = new PrincipalSearcher(query);
        var native = Assert.IsType<DirectorySearcher>(principals.GetUnderlyingSearcher());
        native.PageSize = 0;
        native.ReferralChasing = ReferralChasingOption.None;
        native.ConfigureConnectionOverride = _ => { };
        native.AttributeScopeQuery = "member";
        native.SizeLimit = 7;
        var failure = new InvalidOperationException("controlled attribute-scoped failure");
        const string schemaDn = "CN=Schema,DC=example,DC=test";
        const string memberDn = "CN=member,DC=example,DC=test";
        fixture.Reply = number =>
        {
            var request = fixture.Queries[^1];
            if (number == 1) return SaveResponse("", new() { ["schemaNamingContext"] = [schemaDn] }, 1, ResultCode.Success, false, false);
            if (number == 2) return SaveResponse("CN=Member," + schemaDn, new()
                { ["attributeSyntax"] = ["2.5.5.1"], ["oMSyntax"] = ["127"] }, 1, ResultCode.Success, false, false);
            if (request.Controls.OfType<AsqRequestControl>().Any())
            {
                Assert.Equal(1, native.SizeLimit);
                Assert.Equal(1, request.SizeLimit);
                if (mode == "native-failure") throw failure;
                // A real protocol rejection takes the existing unsupported-ASQ
                // fallback. No native BER decoder/library is needed offline.
                throw new DirectoryOperationException(SaveResponse("", [], 0,
                    ResultCode.UnavailableCriticalExtension, false, false));
            }
            if (request.Attributes.Contains("member"))
            {
                Assert.Equal(1, native.SizeLimit); // Unsupported control did not accept the query.
                if (mode == "fallback-list-failure") throw failure;
                return mode == "fallback-empty" ? EmptyProtocolScopeResponse() :
                    SaveResponse(request.DistinguishedName, new() { ["member"] = [memberDn] }, 1, ResultCode.Success, false, false);
            }
            Assert.Equal(memberDn, request.DistinguishedName);
            Assert.Equal(7, native.SizeLimit); // Complete list accepted before per-DN enumeration.
            Assert.Equal(1, request.SizeLimit);
            throw failure;
        };

        var error = Record.Exception(() => Assert.Null(principals.FindOne()));
        if (mode.EndsWith("empty", StringComparison.Ordinal)) Assert.Null(error);
        else Assert.Same(failure, error);
        Assert.Equal(expectedLimit, native.SizeLimit);
        Assert.Equal(requests, fixture.Queries.Count);
        fixture.AssertReleased();
    }
}
