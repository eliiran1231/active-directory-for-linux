using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class MembershipFixture : IDisposable
    {
        internal const string GroupDn = "CN=group,DC=example", RemovedDn = "CN=removed,DC=example",
            AddedDn = "CN=added,DC=example", KeptDn = "CN=kept,DC=example";
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example");
        internal readonly DirectoryEntry GroupEntry = new("LDAP://offline.invalid/" + GroupDn);
        internal readonly DirectoryEntry RemovedEntry = new("LDAP://offline.invalid/" + RemovedDn);
        internal readonly DirectoryEntry AddedEntry = new("LDAP://offline.invalid/" + AddedDn);
        internal readonly GroupPrincipal Group;
        internal readonly UserPrincipal Removed, Added;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<MembershipTransport> Transports = [];
        internal readonly List<LdapModifyCommand> Invocations = [], Submissions = [];
        internal readonly List<LdapSearchCommand> Reads = [];
        internal readonly HashSet<string> ServerMembers = new(StringComparer.OrdinalIgnoreCase) { RemovedDn, KeptDn };
        internal readonly InvalidOperationException BeforeSend = new("controlled membership failure before submission");
        internal readonly TimeoutException Lost = new("controlled membership response loss");
        internal readonly IOException ReadbackFailure = new("controlled membership refresh failure after acknowledgement");
        internal string Outcome = "success";
        internal bool Capable = true, ApplyLost, FailReadback;
        internal int Admissions, Acknowledgements, PostAckReads;

        internal MembershipFixture()
        {
            var entries = new[] { GroupEntry, RemovedEntry, AddedEntry };
            for (var i = 0; i < entries.Length; i++)
            {
                var index = i;
                entries[i].Options.Referral = ReferralChasingOption.None;
                entries[i].PropertyReadOverride = (_, _) =>
                {
                    if (index == 0 && Acknowledgements > 0)
                    {
                        PostAckReads++;
                        if (FailReadback) throw ReadbackFailure;
                    }
                    var values = new PropertyCollection();
                    values.ReplaceLoaded("objectGUID", [new Guid(index + 1, 0, 0, new byte[8]).ToByteArray()]);
                    values.ReplaceLoaded("objectClass", index == 0 ? ["top", "group"] : ["top", "person", "user"]);
                    values.ReplaceLoaded("objectSid", [CrossContextFixture.SidBytes($"S-1-5-21-10-20-30-{(index == 0 ? 500 : 1000 + index)}")]);
                    values.ReplaceLoaded("primaryGroupID", ["513"]); // actual primary RID differs from group RID500
                    if (index == 0) values.ReplaceLoaded("member", ServerMembers.Cast<object>());
                    return values;
                };
                entries[i].OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                {
                    Admissions++;
                    Assert.Equal(1, count);
                    return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                    {
                        var transport = new MembershipTransport(this);
                        Transports.Add(transport);
                        return new BoundLdapSession(transport, transport, options, new(options), referrals);
                    }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
                };
            }
            Group = Assert.IsType<GroupPrincipal>(Principal.Materialize(Context, typeof(GroupPrincipal), GroupEntry));
            Removed = Assert.IsType<UserPrincipal>(Principal.Materialize(Context, typeof(UserPrincipal), RemovedEntry));
            Added = Assert.IsType<UserPrincipal>(Principal.Materialize(Context, typeof(UserPrincipal), AddedEntry));
        }
        internal void Stage()
        {
            Assert.True(Group.Members.Remove(Removed));
            Group.Members.Add(Added);
            Assert.True(Group.HasReferentialPropertiesSet);
            Assert.True(Group.Members.Contains(Added));
            Assert.False(Group.Members.Contains(Removed));
            Assert.Single(Reads, r => r.Attributes.Contains("member;range=0-*"));
            Assert.Equal(2, Reads.Count); // range and schema-root discovery; literal DNs need no object validation
            AssertReleased(1);
        }
        internal void AssertReleased(int count)
        {
            Assert.Equal(count, Admissions);
            Assert.Equal(count, Transports.Count);
            Assert.All(Transports, t => Assert.Equal(1, t.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose()
        {
            Group.Dispose(); Removed.Dispose(); Added.Dispose();
            GroupEntry.Dispose(); RemovedEntry.Dispose(); AddedEntry.Dispose(); Context.Dispose(); Pool.Dispose();
        }
    }

    private sealed class MembershipTransport(MembershipFixture fixture) : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            (fixture.Capable ? LdapTransportCapabilities.Modify : LdapTransportCapabilities.None);
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            fixture.Reads.Add(command);
            if (command.BaseDn == "") return new(ResultCode.Success, "", null, [], [], [], []);
            var attributes = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase);
            if (!command.Attributes.Contains("1.1"))
            {
                Assert.Equal(MembershipFixture.GroupDn, command.BaseDn);
                Assert.Equal(new[] { "member;range=0-*" }, command.Attributes);
                attributes["member;range=0-*"] = fixture.ServerMembers.Select(Encoding.UTF8.GetBytes).ToArray();
            }
            return new(ResultCode.Success, "", null, [new(command.BaseDn, attributes, [])], [], [], []);
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var modify = Assert.IsType<LdapModifyCommand>(command);
            fixture.Invocations.Add(modify);
            if (fixture.Outcome == "not-sent") throw fixture.BeforeSend;
            submission.BeforeSend(); fixture.Submissions.Add(modify);
            if (fixture.Outcome == "rejected") return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.InsufficientAccessRights, null, "controlled membership rejection", [], []));
            if (fixture.Outcome != "lost" || fixture.ApplyLost)
            {
                Assert.True(fixture.ServerMembers.Remove(MembershipFixture.RemovedDn));
                Assert.True(fixture.ServerMembers.Add(MembershipFixture.AddedDn));
            }
            if (fixture.Outcome == "lost") throw fixture.Lost;
            fixture.Acknowledgements++;
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public void Dispose() => Disposals++;
    }

    private static void AssertMembershipDelta(LdapModifyCommand command)
    {
        Assert.Equal(MembershipFixture.GroupDn, command.DistinguishedName);
        Assert.Empty(command.Controls);
        Assert.Equal(2, command.Changes.Length);
        Assert.All(command.Changes, c => Assert.Equal("member", c.Name));
        Assert.Equal(DirectoryAttributeOperation.Delete, command.Changes[0].Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(MembershipFixture.RemovedDn), Assert.Single(command.Changes[0].Values));
        Assert.Equal(DirectoryAttributeOperation.Add, command.Changes[1].Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(MembershipFixture.AddedDn), Assert.Single(command.Changes[1].Values));
    }

    [Theory]
    [InlineData("success")]
    [InlineData("incapable")]
    [InlineData("not-sent")]
    [InlineData("rejected")]
    public void Neutral_public_group_save_preserves_retryable_member_deltas_and_acknowledges_exact_atomic_change(string outcome)
    {
        using var fixture = new MembershipFixture();
        fixture.Stage();
        fixture.Outcome = outcome; fixture.Capable = outcome != "incapable";
        var error = Record.Exception(fixture.Group.Save);
        if (outcome == "success") Assert.Null(error);
        else
        {
            if (outcome == "incapable") Assert.IsType<PlatformNotSupportedException>(error);
            else if (outcome == "not-sent") Assert.Same(fixture.BeforeSend, error);
            else Assert.IsType<UnauthorizedAccessException>(error);
            Assert.True(fixture.Group.HasReferentialPropertiesSet);
            Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn }, fixture.ServerMembers.OrderBy(s => s, StringComparer.Ordinal));
            Assert.Equal(outcome == "incapable" ? 0 : 1, fixture.Invocations.Count);
            Assert.Equal(outcome == "rejected" ? 1 : 0, fixture.Submissions.Count);
            fixture.AssertReleased(2);
            fixture.Outcome = "success"; fixture.Capable = true;
            fixture.Group.Save();
        }
        Assert.All(fixture.Invocations, AssertMembershipDelta);
        Assert.False(fixture.Group.HasReferentialPropertiesSet);
        Assert.True(fixture.Group.Members.Contains(fixture.Added));
        Assert.False(fixture.Group.Members.Contains(fixture.Removed));
        Assert.Equal(new[] { MembershipFixture.AddedDn, MembershipFixture.KeptDn }, fixture.ServerMembers.OrderBy(s => s, StringComparer.Ordinal));
        var admissions = outcome == "success" ? 2 : 3;
        var writes = fixture.Submissions.Count;
        fixture.Group.Save(); // completed membership is not submitted again
        Assert.Equal(writes, fixture.Submissions.Count);
        Assert.Equal(1, fixture.PostAckReads);
        fixture.AssertReleased(admissions);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Neutral_public_group_lost_membership_response_keeps_pending_delta_without_claiming_server_outcome(bool applied)
    {
        using var fixture = new MembershipFixture();
        fixture.Stage(); fixture.Outcome = "lost"; fixture.ApplyLost = applied;
        Assert.Same(fixture.Lost, Assert.Throws<TimeoutException>(fixture.Group.Save));
        AssertMembershipDelta(Assert.Single(fixture.Submissions));
        Assert.Single(fixture.Invocations);
        Assert.True(fixture.Group.HasReferentialPropertiesSet);
        Assert.True(fixture.Group.Members.Contains(fixture.Added));
        Assert.False(fixture.Group.Members.Contains(fixture.Removed));
        Assert.Equal(applied, fixture.ServerMembers.Contains(MembershipFixture.AddedDn));
        Assert.Equal(!applied, fixture.ServerMembers.Contains(MembershipFixture.RemovedDn));
        Assert.Equal(0, fixture.Acknowledgements);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(2);
        // Pending collection intent is not server evidence. Repeated Save after
        // unknown membership delivery needs a separate contract; do not invent a
        // no-replay/quarantine oracle for this ledger-free immediate write path.
    }

    [Fact]
    public void Neutral_public_group_acknowledged_membership_is_not_replayed_when_postwrite_refresh_fails()
    {
        using var fixture = new MembershipFixture();
        fixture.Stage(); fixture.FailReadback = true;
        Assert.Same(fixture.ReadbackFailure, Assert.Throws<IOException>(fixture.Group.Save));
        AssertMembershipDelta(Assert.Single(fixture.Submissions));
        Assert.Equal(1, fixture.Acknowledgements);
        Assert.Equal(1, fixture.PostAckReads);
        Assert.False(fixture.Group.HasReferentialPropertiesSet);
        fixture.AssertReleased(2);
        fixture.FailReadback = false;
        fixture.Group.Save();
        Assert.Single(fixture.Submissions);
        Assert.Equal(1, fixture.PostAckReads);
        fixture.AssertReleased(2);
    }
}
