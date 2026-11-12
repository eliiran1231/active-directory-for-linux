using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class PropertyLoadRecoveryFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/CN=known,DC=example,DC=test");
        internal readonly Guid Identity = new("11b81e1c-34d8-4544-91ae-39d280495aaa");
        internal readonly List<ReadSeamTransport> Transports = [];
        internal readonly List<LdapSearchCommand> Requests = [];
        internal string Failure = "numeric";
        internal bool Repaired;
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(1, 1, startTimer: false);

        internal PropertyLoadRecoveryFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new ReadSeamTransport(command =>
                    {
                        Requests.Add(command);
                        if (command.BaseDn == "")
                            return Success(TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] }));
                        if (command.BaseDn == "CN=Schema")
                        {
                            if (!Repaired && Failure == "schema-code")
                                return new(ResultCode.Unavailable, "", "controlled schema lookup failure", [], [], [], []);
                            return Success(TransportRow("CN=extensionNumber,CN=Schema", new()
                            {
                                ["lDAPDisplayName"] = ["extensionNumber"],
                                ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"],
                            }));
                        }
                        Assert.Equal("CN=known,DC=example,DC=test", command.BaseDn);
                        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, command.Scope);
                        if (!Repaired && Failure == "directory-code")
                            return new(ResultCode.InsufficientAccessRights, "", "controlled object read failure", [], [], [], []);
                        return Success(TransportRow(command.BaseDn, new()
                        {
                            ["objectGUID"] = [Identity.ToByteArray()],
                            ["description"] = ["loaded description"],
                            ["extensionNumber"] = [!Repaired && Failure == "numeric" ? "invalid-number" : "42"],
                        }));
                    });
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        private static LdapSearchResult Success(params LdapTransportEntry[] entries)
            => new(ResultCode.Success, "", null, entries, [], [], []);

        internal void AssertReleased(int requests)
        {
            Assert.Equal(requests, Requests.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, pool.Snapshot.Total);
            Assert.Equal(0, pool.Snapshot.Waiting);
        }
        public void Dispose() { Entry.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData("numeric", false)]
    [InlineData("numeric", true)]
    [InlineData("schema-code", false)]
    [InlineData("schema-code", true)]
    [InlineData("directory-code", false)]
    [InlineData("directory-code", true)]
    public void Failed_property_load_or_principal_attachment_releases_lease_and_keeps_the_same_entry_retryable(string failure, bool principal)
    {
        using var fixture = new PropertyLoadRecoveryFixture { Failure = failure };
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        var properties = fixture.Entry.Properties;
        Assert.Empty(fixture.Requests);
        var error = Record.Exception(() =>
        {
            if (principal) { using var failedUser = new UserPrincipal(context, fixture.Entry); }
            else _ = properties["description"].Value;
        });
        if (failure == "numeric") Assert.IsType<FormatException>(error);
        else if (!principal)
            Assert.Equal((int)(failure == "directory-code" ? ResultCode.InsufficientAccessRights : ResultCode.Unavailable),
                Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        else if (failure == "directory-code") Assert.IsType<UnauthorizedAccessException>(error);
        else Assert.IsType<PrincipalServerDownException>(error);
        Assert.Single(fixture.Transports);
        var failedRequests = failure == "directory-code" ? 1 : 3;
        fixture.AssertReleased(failedRequests);
        Assert.False(fixture.Entry.IsDisposed);
        Assert.Same(properties, fixture.Entry.Properties);

        fixture.Repaired = true;
        if (principal)
        {
            using var user = new UserPrincipal(context, fixture.Entry);
            Assert.Equal(fixture.Identity, user.Guid);
            Assert.Equal("loaded description", user.Description);
            Assert.Equal(42, Assert.IsType<int>(properties["extensionNumber"].Value));
            Assert.Same(fixture.Entry, user.GetUnderlyingObject());
        }
        else
        {
            Assert.Equal("loaded description", properties["description"].Value);
            Assert.Equal(42, Assert.IsType<int>(properties["extensionNumber"].Value));
            Assert.Equal(fixture.Identity, fixture.Entry.Guid);
            Assert.Same(properties, fixture.Entry.Properties);
        }
        Assert.Equal(2, fixture.Transports.Count);
        fixture.AssertReleased(failedRequests + 3);
        Assert.Equal(2, fixture.Requests.Count(request => request.BaseDn == "CN=known,DC=example,DC=test"));
        // Principal disposal owns its entry; constructing another unsaved query
        // verifies that the caller-owned context remains usable without I/O.
        Assert.Equal(principal, fixture.Entry.IsDisposed);
        using var nextQuery = new UserPrincipal(context);
        Assert.Same(context, nextQuery.Context);
        fixture.AssertReleased(failedRequests + 3);
    }
}
