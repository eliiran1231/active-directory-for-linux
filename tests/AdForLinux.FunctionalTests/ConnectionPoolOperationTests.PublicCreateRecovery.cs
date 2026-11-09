using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class NeutralCreationFixture : IDisposable
    {
        internal readonly DirectoryEntry Parent = new("LDAP://offline.invalid/OU=people,DC=example");
        internal readonly DirectoryEntry Child;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<CreationTransport> Transports = [];
        internal readonly List<LdapMutationCommand> Invocations = [], Submissions = [];
        internal readonly List<LdapSearchCommand> Reads = [];
        internal readonly InvalidOperationException NotSent = new("controlled Add failure before submission");
        internal readonly TimeoutException LostResponse = new("controlled Add response loss after submission");
        internal readonly Dictionary<string, object[]> Server = new(StringComparer.OrdinalIgnoreCase);
        internal string Outcome = "success";
        internal bool Capable = true, ApplyLostAdd;
        internal int Admissions;
        internal const string Dn = "CN=created,OU=people,DC=example";

        internal NeutralCreationFixture()
        {
            Child = Parent.Children.Add("CN=created", "user");
            Child.Options.Referral = ReferralChasingOption.None;
            // NewChild has its own entry recipe. Install the existing transport
            // seam on that public result; do not assume parent hooks propagate.
            Child.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Admissions++;
                Assert.Equal(1, count);
                return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new CreationTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            };
            Child.Properties["cn"].Value = "created";
            Child.Properties["description"].Value = "created café";
        }

        internal void AssertReleased(int admissions)
        {
            Assert.Equal(admissions, Admissions);
            Assert.Equal(admissions, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Child.Dispose(); Parent.Dispose(); Pool.Dispose(); }
    }

    private sealed class CreationTransport(NeutralCreationFixture fixture)
        : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.Modify |
            (fixture.Capable ? LdapTransportCapabilities.Add : LdapTransportCapabilities.None);
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.Reads.Add(command);
            if (command.BaseDn == "") return new(ResultCode.Success, "", null, [], [], [], []); // no AD schema advertised
            Assert.Equal(NeutralCreationFixture.Dn, command.BaseDn);
            if (fixture.Server.Count == 0)
                return new(ResultCode.NoSuchObject, "OU=people,DC=example", "controlled absent object", [], [], [], []);
            var attributes = fixture.Server.Where(p => command.Attributes.Contains("*") ||
                command.Attributes.Contains(p.Key, StringComparer.OrdinalIgnoreCase)).ToDictionary(p => p.Key, p => p.Value);
            return new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, attributes)], [], [], []);
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.Invocations.Add(command);
            if (fixture.Outcome == "not-sent") throw fixture.NotSent;
            submission.BeforeSend();
            fixture.Submissions.Add(command);
            if (fixture.Outcome == "rejected")
                return ValueTask.FromResult(Envelope(ResultCode.InsufficientAccessRights));
            if (fixture.Outcome != "lost" || fixture.ApplyLostAdd)
            {
                if (command is LdapAddCommand add)
                {
                    Assert.Empty(fixture.Server);
                    foreach (var attribute in add.Attributes)
                        fixture.Server[attribute.Name] = attribute.Values.Select(value => (object)Encoding.UTF8.GetString(value)).ToArray();
                }
                else
                    foreach (var change in Assert.IsType<LdapModifyCommand>(command).Changes)
                    {
                        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
                        fixture.Server[change.Name] = change.Values.Select(value => (object)Encoding.UTF8.GetString(value)).ToArray();
                    }
            }
            if (fixture.Outcome == "lost") throw fixture.LostResponse;
            return ValueTask.FromResult(Envelope(ResultCode.Success));
        }
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData("incapable")]
    [InlineData("not-sent")]
    [InlineData("rejected")]
    public void Public_new_child_retains_unsent_or_rejected_Add_then_switches_to_Modify_only_after_acknowledgement(string outcome)
    {
        using var fixture = new NeutralCreationFixture { Outcome = outcome, Capable = outcome != "incapable" };
        var properties = fixture.Child.Properties;
        var description = properties["description"];
        var error = Record.Exception(fixture.Child.CommitChanges);
        if (outcome == "incapable") Assert.IsType<PlatformNotSupportedException>(error);
        else if (outcome == "not-sent") Assert.Same(fixture.NotSent, error);
        else Assert.Equal((int)ResultCode.InsufficientAccessRights, Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        Assert.Same(properties, fixture.Child.Properties);
        Assert.True(description.Changed);
        Assert.Equal("created café", description.Value);
        Assert.Empty(fixture.Server);
        Assert.Empty(fixture.Reads);
        Assert.Equal(outcome == "incapable" ? 0 : 1, fixture.Invocations.Count);
        Assert.Equal(outcome == "rejected" ? 1 : 0, fixture.Submissions.Count);
        fixture.AssertReleased(1);

        fixture.Outcome = "success";
        fixture.Capable = true;
        fixture.Child.CommitChanges();
        var add = Assert.IsType<LdapAddCommand>(fixture.Submissions.Last());
        Assert.Equal(NeutralCreationFixture.Dn, add.DistinguishedName);
        Assert.Equal(new[] { "cn", "description", "objectClass" }, add.Attributes.Select(a => a.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(Encoding.UTF8.GetBytes("created café"), Assert.Single(add.Attributes.Single(a => a.Name == "description").Values));
        Assert.False(description.Changed);
        fixture.AssertReleased(2);
        var acknowledged = fixture.Submissions.Count;
        fixture.Child.CommitChanges();
        Assert.Equal(acknowledged, fixture.Submissions.Count);
        fixture.AssertReleased(2);

        // This public edit loads the acknowledged entry through the real neutral
        // property reader, then must issue Modify rather than repeat Add.
        fixture.Child.Properties["description"].Value = "later";
        Assert.Equal(2, fixture.Reads.Count); // object plus empty schema-root discovery
        fixture.AssertReleased(3);
        fixture.Child.CommitChanges();
        var modify = Assert.IsType<LdapModifyCommand>(fixture.Submissions.Last());
        Assert.Equal(NeutralCreationFixture.Dn, modify.DistinguishedName);
        var change = Assert.Single(modify.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(Encoding.UTF8.GetBytes("later"), Assert.Single(change.Values));
        Assert.Equal("later", Assert.Single(fixture.Server["description"]));
        Assert.Equal(acknowledged + 1, fixture.Submissions.Count);
        fixture.AssertReleased(4);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_new_child_lost_Add_response_preserves_creation_quarantine_after_real_neutral_readback(bool applied)
    {
        using var fixture = new NeutralCreationFixture { Outcome = "lost", ApplyLostAdd = applied };
        var properties = fixture.Child.Properties;
        var description = properties["description"];
        var path = fixture.Child.Path;
        Assert.Same(fixture.LostResponse, Assert.Throws<TimeoutException>(fixture.Child.CommitChanges));
        Assert.IsType<LdapAddCommand>(Assert.Single(fixture.Submissions));
        fixture.AssertReleased(1);
        Assert.Throws<InvalidOperationException>(fixture.Child.CommitChanges);
        fixture.AssertReleased(1); // refusal happens before another admission

        var error = Record.Exception(() => fixture.Child.RefreshCache(["cn", "objectClass", "description"]));
        if (applied) Assert.Contains("Add outcome is uncertain", Assert.IsType<InvalidOperationException>(error).Message);
        else Assert.Equal((int)ResultCode.NoSuchObject, Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        Assert.Equal(applied ? 2 : 1, fixture.Reads.Count);
        Assert.Same(properties, fixture.Child.Properties);
        Assert.Same(description, fixture.Child.Properties["description"]);
        Assert.Equal("created café", description.Value);
        Assert.True(description.Changed);
        Assert.Equal(path, fixture.Child.Path);
        Assert.False(fixture.Child.IsDisposed);
        Assert.Throws<InvalidOperationException>(fixture.Child.CommitChanges);
        Assert.Single(fixture.Invocations);
        Assert.Single(fixture.Submissions);
        fixture.AssertReleased(2);
        // Server rows are fixture facts, not evidence of who created a real AD
        // object. Neither absence nor matching same-DN values release this handle.
    }
}
