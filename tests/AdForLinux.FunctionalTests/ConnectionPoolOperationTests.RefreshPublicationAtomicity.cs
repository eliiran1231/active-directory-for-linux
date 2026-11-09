using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class RefreshAtomicityFixture : IDisposable
    {
        internal const string Dn = "CN=known,DC=example";
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/" + Dn);
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<RefreshAtomicityTransport> Transports = [];
        internal readonly List<LdapSearchCommand> Reads = [];
        internal readonly List<LdapModifyCommand> Writes = [];
        internal string Description = "initial description", Number = "1";
        internal RefreshAtomicityFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new RefreshAtomicityTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        internal void AssertReleased(int operations, int reads, int writes)
        {
            Assert.Equal(operations, Transports.Count);
            Assert.Equal(reads, Reads.Count);
            Assert.Equal(writes, Writes.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Entry.Dispose(); Pool.Dispose(); }
    }

    private sealed class RefreshAtomicityTransport(RefreshAtomicityFixture fixture)
        : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.Modify;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); fixture.Reads.Add(command);
            LdapTransportEntry row;
            if (command.BaseDn == "")
            {
                Assert.Equal(new[] { "schemaNamingContext" }, command.Attributes);
                row = TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] });
            }
            else if (command.BaseDn == "CN=Schema")
            {
                Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, command.Scope);
                Assert.Contains("(lDAPDisplayName=extensionNumber)", command.Filter, StringComparison.Ordinal);
                row = TransportRow("CN=extensionNumber,CN=Schema", new()
                {
                    ["lDAPDisplayName"] = ["extensionNumber"],
                    ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"],
                });
            }
            else
            {
                Assert.Equal(RefreshAtomicityFixture.Dn, command.BaseDn);
                Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, command.Scope);
                row = TransportRow(command.BaseDn, new()
                {
                    ["description"] = [fixture.Description],
                    ["extensionNumber"] = [fixture.Number],
                });
            }
            return new(ResultCode.Success, "", null, [row], [], [], []);
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); submission.BeforeSend();
            var modify = Assert.IsType<LdapModifyCommand>(command);
            fixture.Writes.Add(modify);
            foreach (var change in modify.Changes)
            {
                Assert.Equal("description", change.Name);
                Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
                fixture.Description = Encoding.UTF8.GetString(Assert.Single(change.Values));
            }
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Failed_public_refresh_preserves_published_cache_and_unsent_entry_edit_before_commit_and_recovery(bool full)
    {
        using var fixture = new RefreshAtomicityFixture();
        var cache = fixture.Entry.Properties;
        var pending = cache["description"];
        Assert.Equal("initial description", pending.Value);
        Assert.Equal(1, Assert.IsType<int>(cache["extensionNumber"].Value));
        fixture.AssertReleased(1, 3, 0);
        pending.Value = "unsent caller edit";
        fixture.Description = "remote value from failed refresh";
        fixture.Number = "not-a-number";

        Assert.Throws<FormatException>(() =>
        {
            if (full) fixture.Entry.RefreshCache();
            else fixture.Entry.RefreshCache(["description", "extensionNumber"]);
        });
        Assert.Same(cache, fixture.Entry.Properties);
        Assert.Same(pending, fixture.Entry.Properties["description"]);
        Assert.Equal("unsent caller edit", pending.Value);
        Assert.Equal(1, Assert.IsType<int>(cache["extensionNumber"].Value));
        fixture.AssertReleased(2, 6, 0); // access after failure must use retained published cache
        Assert.Equal(full ? new[] { "*", "nTSecurityDescriptor" } : new[] { "description", "extensionNumber" },
            fixture.Reads[3].Attributes);

        // This public write proves the unsent ledger survived the failed typed
        // refresh; retained getters alone would not establish that property.
        fixture.Entry.CommitChanges();
        var write = Assert.Single(fixture.Writes);
        Assert.Equal(RefreshAtomicityFixture.Dn, write.DistinguishedName);
        Assert.Empty(write.Controls);
        var change = Assert.Single(write.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes("unsent caller edit"), Assert.Single(change.Values));
        Assert.Equal("unsent caller edit", fixture.Description);
        fixture.AssertReleased(3, 6, 1);
        fixture.Entry.CommitChanges();
        fixture.AssertReleased(3, 6, 1);

        // A successful refresh is allowed to replace cache contents. Do it only
        // after acknowledgement, avoiding any invented preserve-unsent-on-success
        // or retained-principal reconciliation contract.
        fixture.Description = "healthy remote value";
        fixture.Number = "7";
        if (full) fixture.Entry.RefreshCache();
        else fixture.Entry.RefreshCache(["description", "extensionNumber"]);
        Assert.Equal("healthy remote value", fixture.Entry.Properties["description"].Value);
        Assert.Equal(7, Assert.IsType<int>(fixture.Entry.Properties["extensionNumber"].Value));
        fixture.AssertReleased(4, 9, 1);
        fixture.Entry.CommitChanges();
        fixture.AssertReleased(4, 9, 1);
        // Controlled normalized data; not native decoding, AD server behavior,
        // Microsoft parity, conversion-order timing or concurrency evidence.
    }
}
