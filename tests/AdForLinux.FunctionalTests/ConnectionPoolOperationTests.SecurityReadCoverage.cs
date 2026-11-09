using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class NeutralSecurityReadFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/CN=known,DC=example,DC=test");
        internal readonly List<LdapSearchCommand> Requests = [];
        internal readonly List<ReadSeamTransport> Transports = [];
        internal byte[] Raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)));
        internal ResultCode Code = ResultCode.Success;
        internal string Shape = "valid";
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(1, 1, startTimer: false);

        internal NeutralSecurityReadFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new ReadSeamTransport(command =>
                    {
                        Requests.Add(command);
                        var attributes = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase);
                        if (Shape != "omitted") attributes["nTSecurityDescriptor"] = Shape switch
                        {
                            "empty-values" => [], "empty-bytes" => [[]], "short-header" => [[1, 0, 0, 128]],
                            _ => [Raw],
                        };
                        return new(Code, "", "controlled security read", [new(command.BaseDn, attributes, [])], [], [], []);
                    });
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }

        internal void AssertReleased(int count)
        {
            Assert.Equal(count, Requests.Count);
            Assert.Equal(count, Transports.Count);
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(0, pool.Snapshot.Total);
        }

        public void Dispose() { Entry.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData(EntryMasks.Owner, 1)]
    [InlineData(EntryMasks.Dacl, 4)]
    [InlineData(EntryMasks.Owner | EntryMasks.Dacl, 5)]
    [InlineData(EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl, 15)]
    public void Public_security_read_preserves_requested_sections_binary_snapshot_and_cached_facade(EntryMasks masks, byte wireMask)
    {
        using var fixture = new NeutralSecurityReadFixture();
        fixture.Entry.Options.SecurityMasks = masks;
        var expected = fixture.Raw.ToArray();

        var security = fixture.Entry.ObjectSecurity;

        Assert.Equal(masks, security.RetrievedMasks);
        Assert.Equal(expected, security.GetSecurityDescriptorBinaryForm());
        Assert.Same(security, fixture.Entry.ObjectSecurity);
        fixture.Raw[0] = 42; // caller-owned transport response must not back the facade
        Assert.Equal(expected, security.GetSecurityDescriptorBinaryForm());
        var request = Assert.Single(fixture.Requests);
        Assert.Equal("CN=known,DC=example,DC=test", request.BaseDn);
        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.Base, request.Scope);
        Assert.Equal("(objectClass=*)", request.Filter);
        Assert.Equal(new[] { "nTSecurityDescriptor" }, request.Attributes);
        var control = Assert.Single(request.Controls!);
        Assert.Equal("1.2.840.113556.1.4.801", control.Oid);
        Assert.Equal(new byte[] { 0x30, 3, 2, 1, wireMask }, control.Value);
        Assert.True(control.Critical);
        Assert.True(control.HasValue);
        fixture.AssertReleased(1);
    }

    [Theory]
    [InlineData("omitted")]
    [InlineData("empty-values")]
    [InlineData("empty-bytes")]
    [InlineData("short-header")]
    public void Public_security_read_failure_does_not_cache_an_unusable_descriptor(string shape)
    {
        using var fixture = new NeutralSecurityReadFixture();
        fixture.Entry.Options.SecurityMasks = EntryMasks.Dacl;
        fixture.Shape = shape;

        var failure = Record.Exception(() => _ = fixture.Entry.ObjectSecurity);

        if (shape is "omitted" or "empty-values") Assert.IsType<InvalidOperationException>(failure);
        else Assert.IsAssignableFrom<ArgumentException>(failure);
        fixture.AssertReleased(1);
        fixture.Shape = "valid";
        var repaired = fixture.Entry.ObjectSecurity;
        Assert.Equal(fixture.Raw, repaired.GetSecurityDescriptorBinaryForm());
        Assert.Same(repaired, fixture.Entry.ObjectSecurity);
        fixture.AssertReleased(2);
    }

    [Theory]
    [InlineData(ResultCode.InsufficientAccessRights)]
    [InlineData(ResultCode.NoSuchObject)]
    [InlineData(ResultCode.Unavailable)]
    public void Public_security_read_propagates_LDAP_failure_and_accepts_a_later_success(ResultCode code)
    {
        using var fixture = new NeutralSecurityReadFixture();
        fixture.Entry.Options.SecurityMasks = EntryMasks.Owner | EntryMasks.Dacl;
        fixture.Code = code;

        var failure = Assert.Throws<DirectoryServicesCOMException>(() => _ = fixture.Entry.ObjectSecurity);

        Assert.Equal((int)code, failure.ExtendedError);
        fixture.AssertReleased(1);
        fixture.Code = ResultCode.Success;
        Assert.Equal(fixture.Raw, fixture.Entry.ObjectSecurity.GetSecurityDescriptorBinaryForm());
        fixture.AssertReleased(2);
    }
}
