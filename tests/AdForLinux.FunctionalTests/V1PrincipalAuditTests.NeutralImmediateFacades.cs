using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class ImmediateFacadeFixture : IDisposable
    {
        internal const string Dn = "CN=item,OU=source,DC=example", DestinationDn = "OU=destination,DC=example";
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example");
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/" + Dn);
        internal readonly DirectoryEntry Destination;
        internal readonly UserPrincipal User;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<ImmediateFacadeTransport> Transports = [];
        internal readonly List<LdapMutationCommand> Commands = [];
        internal readonly List<LdapSearchCommand> Reads = [];
        internal readonly TimeoutException Lost = new("controlled immediate facade response loss");
        internal bool LoseResponse;
        internal ResultCode Result = ResultCode.InsufficientAccessRights;
        internal int Admissions;
        internal ImmediateFacadeFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.PropertyReadOverride = (_, _) =>
            {
                var values = new PropertyCollection();
                values.ReplaceLoaded("objectGUID", [new Guid("231024f2-2276-4be7-bc50-456ee1859540").ToByteArray()]);
                values.ReplaceLoaded("objectClass", ["top", "person", "user"]);
                values.ReplaceLoaded("description", ["retained source cache"]);
                return values;
            };
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Admissions++; Assert.Equal(1, count);
                return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new ImmediateFacadeTransport(this); Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            };
            Destination = Entry.CreateEntryForDn(DestinationDn);
            User = Assert.IsType<UserPrincipal>(Principal.Materialize(Context, typeof(UserPrincipal), Entry));
        }
        internal void Invoke(string mode)
        {
            if (mode == "delete") User.Delete();
            else if (mode == "rename") Entry.Rename("CN=renamed");
            else Entry.MoveTo(Destination, "CN=renamed");
        }
        internal void AssertReleased()
        {
            Assert.Equal(Admissions, Transports.Count);
            Assert.All(Transports, t => Assert.Equal(1, t.Disposals));
            Assert.Equal(Reads.Count + Commands.Count, Admissions); // one request per public acquired lease
            Assert.All(Reads, read => Assert.Equal(new[] { "1.1" }, read.Attributes));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { User.Dispose(); Entry.Dispose(); Destination.Dispose(); Context.Dispose(); Pool.Dispose(); }
    }

    private sealed class ImmediateFacadeTransport(ImmediateFacadeFixture fixture) : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.Delete | LdapTransportCapabilities.ModifyDn;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); fixture.Reads.Add(command);
            return new(ResultCode.Success, "", null, [new(command.BaseDn, new(StringComparer.OrdinalIgnoreCase), [])], [], [], []);
        }
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); submission.BeforeSend(); fixture.Commands.Add(command);
            if (fixture.LoseResponse) throw fixture.Lost;
            return ValueTask.FromResult(new LdapResultEnvelope(fixture.Result, null, "controlled facade result", [], []));
        }
        public void Dispose() => Disposals++;
    }

    private static void AssertImmediateFacadeCommand(LdapMutationCommand command, string mode)
    {
        Assert.Equal(ImmediateFacadeFixture.Dn, command.DistinguishedName);
        Assert.Empty(command.Controls);
        if (mode == "delete") Assert.IsType<LdapDeleteCommand>(command); // direct child delete, never TreeDeleteControl
        else
        {
            var rename = Assert.IsType<LdapModifyDnCommand>(command);
            Assert.Equal("CN=renamed", rename.NewRdn);
            Assert.True(rename.DeleteOldRdn);
            Assert.Equal(mode == "move" ? ImmediateFacadeFixture.DestinationDn : "OU=source,DC=example", rename.NewSuperior);
        }
    }

    [Theory]
    [InlineData("delete", false)]
    [InlineData("rename", false)]
    [InlineData("move", false)]
    [InlineData("delete", true)]
    [InlineData("rename", true)]
    [InlineData("move", true)]
    public void Neutral_public_delete_move_rename_preserve_local_state_after_failure_and_release_every_lease(string mode, bool lost)
    {
        using var fixture = new ImmediateFacadeFixture { LoseResponse = lost };
        var path = fixture.Entry.Path;
        var error = Record.Exception(() => fixture.Invoke(mode));
        if (lost) Assert.Same(fixture.Lost, error);
        else if (mode == "delete") Assert.IsType<UnauthorizedAccessException>(error);
        else Assert.Equal((int)ResultCode.InsufficientAccessRights, Assert.IsType<DirectoryServicesCOMException>(error).ExtendedError);
        AssertImmediateFacadeCommand(Assert.Single(fixture.Commands), mode);
        fixture.AssertReleased();
        Assert.Equal(mode == "move" ? 1 : 2, fixture.Admissions);
        Assert.False(fixture.User.IsDeleted);
        Assert.False(fixture.Entry.IsDisposed);
        Assert.Same(fixture.Entry, fixture.User.GetUnderlyingObject());
        Assert.Equal(path, fixture.Entry.Path);
        Assert.Equal("retained source cache", fixture.Entry.Properties["description"].Value);
        if (lost) return; // local state does not establish whether a real server applied this operation

        fixture.Result = ResultCode.Success;
        fixture.Invoke(mode); // explicit caller retry only after definitive rejection
        Assert.Equal(2, fixture.Commands.Count);
        Assert.All(fixture.Commands, command => AssertImmediateFacadeCommand(command, mode));
        fixture.AssertReleased();
        Assert.Equal(mode == "move" ? 2 : 3, fixture.Admissions);
        if (mode == "delete")
        {
            Assert.True(fixture.User.IsDeleted);
            Assert.True(fixture.Entry.IsDisposed);
            Assert.Throws<InvalidOperationException>(fixture.User.Delete);
            Assert.Equal(2, fixture.Commands.Count);
        }
        else
        {
            Assert.False(fixture.Entry.IsDisposed);
            Assert.Equal("LDAP://offline.invalid/CN=renamed," +
                (mode == "move" ? ImmediateFacadeFixture.DestinationDn : "OU=source,DC=example"), fixture.Entry.Path);
        }
    }
}
