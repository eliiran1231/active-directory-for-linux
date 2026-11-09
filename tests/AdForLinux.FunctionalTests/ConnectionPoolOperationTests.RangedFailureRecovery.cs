using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class RangedRecoveryFixture : IDisposable
    {
        internal const string GroupDn = "CN=group,DC=example,DC=test";
        internal const string FirstDn = "CN=first,DC=example,DC=test";
        internal const string SecondDn = "CN=second,DC=example,DC=test";
        internal const string LastDn = "CN=last,DC=example,DC=test";
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/" + GroupDn);
        internal readonly List<(ReadSeamTransport Transport, LdapSearchCommand Request)> Requests = [];
        internal readonly List<ReadSeamTransport> Transports = [];
        internal string Failure = "";
        internal bool Repaired;
        internal bool Binary;
        internal Action? DuringContinuation;
        internal readonly byte[] FirstSid = SecurityDescriptorFixtures.U1.ToArray();
        internal readonly byte[] LastSid = SecurityDescriptorFixtures.U2.ToArray();
        internal readonly List<byte[]> ReturnedBinaryBuffers = [];
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(1, 1, startTimer: false);

        internal RangedRecoveryFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    ReadSeamTransport? transport = null;
                    transport = new ReadSeamTransport(command =>
                    {
                        Requests.Add((transport!, command));
                        if (command.BaseDn != "CN=Schema")
                            Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, command.Scope);
                        if (command.BaseDn == "")
                            return Success(TransportRow("", new() { ["schemaNamingContext"] = ["CN=Schema"] }));
                        if (command.BaseDn == "CN=Schema")
                        {
                            Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, command.Scope);
                            if (!Repaired && Failure == "schema-code")
                                return new(ResultCode.ProtocolError, "", "controlled schema failure", [], [], [], []);
                            return Success(TransportRow("CN=attribute,CN=Schema", new()
                            {
                                ["lDAPDisplayName"] = [Binary ? "sIDHistory" : "member"],
                                ["attributeSyntax"] = [Binary ? "2.5.5.17" : "2.5.5.1"],
                                ["oMSyntax"] = [Binary ? "4" : "127"],
                            }));
                        }
                        Assert.Equal(GroupDn, command.BaseDn);
                        var attribute = Assert.Single(command.Attributes);
                        if (attribute == (Binary ? "sIDHistory;range=0-*" : "member;range=0-*"))
                        {
                            if (!Repaired && Failure == "range-end-overflow")
                                return Success(TransportRow(GroupDn, new() { ["member;range=0-2147483647"] = [FirstDn, SecondDn] }));
                            var first = TransportRow(GroupDn, Binary
                                ? new() { ["sIDHistory;range=0-0"] = [FirstSid] }
                                : new() { ["member;range=0-1"] = [FirstDn, SecondDn] });
                            if (Binary) ReturnedBinaryBuffers.Add(first.Attributes["sIDHistory;range=0-0"][0]);
                            return Success(first);
                        }
                        Assert.Equal(Binary ? "sIDHistory;range=1-*" : "member;range=2-*", attribute);
                        DuringContinuation?.Invoke();
                        if (!Repaired && Failure == "continuation-code")
                            return new(ResultCode.Unavailable, "", "controlled continuation failure", [], [], [], []);
                        if (!Repaired && Failure == "continuation-throw")
                            throw new IOException("controlled range response loss");
                        if (!Repaired && Failure == "noncontiguous")
                            return Success(TransportRow(GroupDn, new() { ["member;range=3-*"] = [LastDn] }));
                        var last = TransportRow(GroupDn, Binary
                            ? new() { ["sIDHistory;range=1-*"] = [LastSid] }
                            : new() { ["member;range=2-*"] = [LastDn] });
                        if (Binary) ReturnedBinaryBuffers.Add(last.Attributes["sIDHistory;range=1-*"][0]);
                        return Success(last);
                    });
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        private static LdapSearchResult Success(params LdapTransportEntry[] entries)
            => new(ResultCode.Success, "", null, entries, [], [], []);

        internal void AssertReleased(int sessions, int requests)
        {
            Assert.Equal(sessions, Transports.Count);
            Assert.Equal(requests, Requests.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, pool.Snapshot.Total);
            Assert.Equal(0, pool.Snapshot.Waiting);
        }

        internal string[] RangesFor(ReadSeamTransport transport)
            => Requests.Where(item => ReferenceEquals(item.Transport, transport)
                    && item.Request.BaseDn == GroupDn)
                .Select(item => Assert.Single(item.Request.Attributes)).ToArray();

        public void Dispose() { Entry.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData("continuation-code")]
    [InlineData("continuation-throw")]
    [InlineData("noncontiguous")]
    [InlineData("schema-code")]
    public void Ranged_member_failure_releases_the_single_capacity_lease_and_retry_restarts_at_zero(string failure)
    {
        using var fixture = new RangedRecoveryFixture { Failure = failure };
        var error = Record.Exception(() => RangedAttributeReader.Read(fixture.Entry, "member"));
        if (failure == "continuation-throw") Assert.IsType<IOException>(error);
        else if (failure == "noncontiguous") Assert.IsType<InvalidOperationException>(error);
        else Assert.Equal((int)(failure == "schema-code" ? ResultCode.ProtocolError : ResultCode.Unavailable),
            Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        var failedReads = failure == "schema-code" ? 3 : 4;
        fixture.AssertReleased(1, failedReads);
        Assert.Equal(failure == "schema-code" ? new[] { "member;range=0-*" }
            : new[] { "member;range=0-*", "member;range=2-*" }, fixture.RangesFor(fixture.Transports[0]));

        fixture.Repaired = true;
        Assert.Equal(new object[] { RangedRecoveryFixture.FirstDn, RangedRecoveryFixture.SecondDn, RangedRecoveryFixture.LastDn },
            RangedAttributeReader.Read(fixture.Entry, "member"));
        fixture.AssertReleased(2, failedReads + 4);
        Assert.Equal(new[] { "member;range=0-*", "member;range=2-*" }, fixture.RangesFor(fixture.Transports[1]));
        Assert.All(fixture.Transports, transport => Assert.Equal(1,
            fixture.Requests.Count(item => ReferenceEquals(item.Transport, transport) && item.Request.BaseDn == "CN=Schema")));
    }

    [Fact]
    public void Public_group_contains_does_not_cache_a_partial_membership_after_a_failed_continuation()
    {
        using var fixture = new RangedRecoveryFixture { Failure = "continuation-code" };
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        static PropertyCollection IdentityProperties(Guid identity)
        {
            var values = new PropertyCollection();
            values.ReplaceLoaded("objectGUID", [identity.ToByteArray()]);
            return values;
        }
        fixture.Entry.PropertyReadOverride = (_, _) => IdentityProperties(new Guid("436a716e-9674-477d-bcfa-c855a773f29d"));
        using var group = new GroupPrincipal(context, fixture.Entry);
        using var memberEntry = new DirectoryEntry("LDAP://offline.invalid/" + RangedRecoveryFixture.LastDn);
        memberEntry.PropertyReadOverride = (_, _) => IdentityProperties(new Guid("e1c568b1-f173-4498-950a-86f5ba1ec3c3"));
        using var member = new UserPrincipal(context, memberEntry);

        Assert.Throws<PrincipalServerDownException>(() => group.Members.Contains(member));
        fixture.AssertReleased(1, 4);
        fixture.Repaired = true;
        Assert.True(group.Members.Contains(member));
        fixture.AssertReleased(2, 8);
        Assert.True(group.Members.Contains(member));
        fixture.AssertReleased(2, 8); // only a complete successful small-group lookup is cached
        Assert.Equal(new[] { "member;range=0-*", "member;range=2-*" }, fixture.RangesFor(fixture.Transports[1]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Closing_or_disposing_entry_during_range_continuation_releases_the_operation_without_returning_prefix(bool dispose)
    {
        using var fixture = new RangedRecoveryFixture();
        fixture.DuringContinuation = () =>
        {
            fixture.DuringContinuation = null;
            if (dispose) fixture.Entry.Dispose();
            else fixture.Entry.Close();
        };
        if (dispose) Assert.Throws<ObjectDisposedException>(() => RangedAttributeReader.Read(fixture.Entry, "member"));
        else Assert.Throws<InvalidOperationException>(() => RangedAttributeReader.Read(fixture.Entry, "member"));
        fixture.AssertReleased(1, 4);
        if (dispose)
        {
            Assert.Throws<ObjectDisposedException>(() => RangedAttributeReader.Read(fixture.Entry, "member"));
            fixture.AssertReleased(1, 4);
        }
        else
        {
            Assert.Equal(new object[] { RangedRecoveryFixture.FirstDn, RangedRecoveryFixture.SecondDn, RangedRecoveryFixture.LastDn },
                RangedAttributeReader.Read(fixture.Entry, "member"));
            fixture.AssertReleased(2, 8);
        }
    }

    [Fact]
    public void Ranged_binary_identity_values_are_owned_copies_after_lease_disposal()
    {
        using var fixture = new RangedRecoveryFixture { Binary = true };
        var first = fixture.FirstSid.ToArray();
        var last = fixture.LastSid.ToArray();
        var values = RangedAttributeReader.Read(fixture.Entry, "sIDHistory");
        fixture.AssertReleased(1, 4);
        Assert.Equal(2, fixture.ReturnedBinaryBuffers.Count);
        foreach (var buffer in fixture.ReturnedBinaryBuffers) Array.Fill(buffer, (byte)99);
        fixture.FirstSid[0] = 99;
        fixture.LastSid[0] = 99;
        Assert.Equal(2, values.Count);
        Assert.Equal(first, Assert.IsType<byte[]>(values[0]));
        Assert.Equal(last, Assert.IsType<byte[]>(values[1]));
        Assert.Equal(new[] { "sIDHistory;range=0-*", "sIDHistory;range=1-*" }, fixture.RangesFor(fixture.Transports[0]));
    }
}
