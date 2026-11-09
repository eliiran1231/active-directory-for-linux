using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using AM = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class TextBoundaryFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly List<TextBoundaryTransport> Transports = [];
        internal readonly List<LdapSearchCommand> Buffered = [], Opened = [];
        internal readonly List<LdapModifyDnCommand> Mutations = [];
        internal int ClosedCursors;
        internal Func<LdapSearchCommand, LdapSearchResult> Reply = command =>
            new(ResultCode.Success, "", null, [TransportRow(command.BaseDn, new())], [], [], []);
        internal TextBoundaryFixture(string dn = "CN=before,OU=source,DC=example")
        {
            Entry = new DirectoryEntry("LDAP://offline.invalid/" + dn);
            Configure(Entry);
        }
        internal void Configure(DirectoryEntry entry)
        {
            entry.Options.Referral = ReferralChasingOption.None;
            entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new TextBoundaryTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        internal void AssertReleased()
        {
            Assert.All(Transports, transport => Assert.Equal(1, transport.Disposals));
            Assert.Equal(Opened.Count, ClosedCursors);
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { Entry.Dispose(); Pool.Dispose(); }
    }

    private sealed class TextBoundaryTransport(TextBoundaryFixture fixture)
        : ILdapConversationTransport, ILdapMutationTransport, ILdapSearchCursor, IDisposable
    {
        internal int Disposals;
        private bool ended;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.ModifyDn;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
        { token.ThrowIfCancellationRequested(); fixture.Buffered.Add(command); return fixture.Reply(command); }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.Equal(0, pageSize);
            fixture.Opened.Add(command); return ValueTask.FromResult<ILdapSearchCursor>(this);
        }
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Assert.False(ended); ended = true;
            return ValueTask.FromResult<LdapSearchEvent>(new LdapSearchEvent.PageEnd(new(ResultCode.Success, null, null, [], []), false));
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken token, TimeSpan? serverTimeLimit = null)
            => throw new InvalidOperationException("Unpaged text boundary query advanced a page.");
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken token)
            => throw new InvalidOperationException("Unexpected Modify in text boundary fixture.");
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); submission.BeforeSend();
            fixture.Mutations.Add(Assert.IsType<LdapModifyDnCommand>(command));
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public ValueTask DisposeAsync() { fixture.ClosedCursors++; return ValueTask.CompletedTask; }
        public void Dispose() => Disposals++;
    }

    [Fact]
    public void Public_SchemaEntry_escapes_server_class_value_without_reinterpreting_schema_DNs()
    {
        using var fixture = new TextBoundaryFixture();
        const string hostileClass = "odd*)(objectClass=*)\\\0é😀";
        const string schemaDn = @"CN=Schema\,branch,DC=example";
        const string classDn = @"CN=odd\,class+UID=7,CN=Schema\,branch,DC=example";
        fixture.Entry.PropertyReadOverride = (_, _) =>
        {
            var values = new PropertyCollection(); values.ReplaceLoaded("objectClass", ["top", hostileClass]); return values;
        };
        fixture.Reply = command => command.BaseDn == ""
            ? new(ResultCode.Success, "", null, [TransportRow("", new() { ["schemaNamingContext"] = [schemaDn] })], [], [], [])
            : new(ResultCode.Success, "", null, [TransportRow(classDn, new() { ["lDAPDisplayName"] = [hostileClass] })], [], [], []);

        using var schema = fixture.Entry.SchemaEntry;
        Assert.Equal("LDAP://offline.invalid/" + classDn, schema.Path);
        Assert.Equal(2, fixture.Buffered.Count);
        Assert.Equal("", fixture.Buffered[0].BaseDn);
        Assert.Equal(new[] { "schemaNamingContext" }, fixture.Buffered[0].Attributes);
        var request = fixture.Buffered[1];
        Assert.Equal(schemaDn, request.BaseDn);
        Assert.Equal(System.DirectoryServices.Protocols.SearchScope.OneLevel, request.Scope);
        Assert.Equal("(&(objectClass=classSchema)(lDAPDisplayName=odd\\2a\\29\\28objectClass=\\2a\\29\\5c\\00é😀))", request.Filter);
        Assert.Equal(new[] { "lDAPDisplayName" }, request.Attributes);
        _ = schema.Properties; // returned recipe/cache wrapper remains lazy
        Assert.Equal(2, fixture.Buffered.Count);
        Assert.Empty(fixture.Opened);
        Assert.Empty(fixture.Mutations);
        fixture.AssertReleased();
        // Synthetic malformed server metadata is not a claim that AD permits
        // such an objectClass. This asserts literal filter construction only.
    }

    [Fact]
    public void Public_raw_filter_NUL_refuses_before_cursor_while_QBE_NUL_is_escaped_as_value()
    {
        using var fixture = new TextBoundaryFixture();
        fixture.Entry.BindEntry(); // isolate application-filter dispatch from root validation
        using var raw = new DirectorySearcher(fixture.Entry) { Filter = "(cn=a\0b)", ReferralChasing = ReferralChasingOption.None };
        var error = Assert.Throws<ArgumentException>(() => raw.FindOne());
        Assert.Contains("NUL", error.Message, StringComparison.Ordinal);
        Assert.Empty(fixture.Opened);
        Assert.Single(fixture.Buffered);
        fixture.AssertReleased();
        raw.Filter = @"(cn=a\00b)";
        Assert.Null(raw.FindOne());
        Assert.Equal(@"(cn=a\00b)", Assert.Single(fixture.Opened).Filter);

        using var context = new AM.PrincipalContext(AM.ContextType.Domain, "offline.invalid", "DC=example");
        fixture.Configure(context.SearchRoot);
        using var query = new AM.UserPrincipal(context) { DisplayName = "team*)(cn=*)\0é😀" };
        using var principalSearcher = new AM.PrincipalSearcher(query);
        var underlying = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        underlying.PageSize = 0;
        underlying.ReferralChasing = ReferralChasingOption.None;
        Assert.Null(principalSearcher.FindOne());
        Assert.Equal(2, fixture.Opened.Count);
        Assert.Equal("(&(objectCategory=user)(objectClass=user)(displayName=team*\\29\\28cn=*\\29\\00é😀))", fixture.Opened[1].Filter);
        Assert.DoesNotContain('\0', fixture.Opened[1].Filter);
        Assert.Equal(1, fixture.Opened[1].SizeLimit);
        Assert.Empty(fixture.Mutations);
        fixture.AssertReleased();
        // QBE intentionally retains unquoted wildcard stars. It is distinct
        // from literal-identity escaping and from a raw LDAP filter string.
    }

    [Theory]
    [InlineData(@"CN=odd\,part+UID=42", @"OU=source\,ou,DC=example", @"OU=dest\,ou,DC=example")]
    [InlineData(@"CN=even\\", "OU=source,DC=example", "OU=dest,DC=example")]
    [InlineData(@"CN=é😀/literal\,part+UID=7", @"OU=source\2cou,DC=example", @"OU=dest\5cunit,DC=example")]
    public void Public_name_parent_and_move_preserve_escaped_RDN_boundaries(string rdn, string parentDn, string destinationDn)
    {
        var sourceDn = rdn + "," + parentDn;
        using var fixture = new TextBoundaryFixture(sourceDn);
        Assert.Equal(rdn, fixture.Entry.Name);
        using (var parent = fixture.Entry.Parent) Assert.Equal(parentDn, parent!.DistinguishedName);
        using var destination = new DirectoryEntry("LDAP://offline.invalid/" + destinationDn);
        fixture.Configure(destination);
        fixture.Entry.MoveTo(destination); // no newName: preserve the complete existing RDN
        var command = Assert.Single(fixture.Mutations);
        Assert.Equal(sourceDn, command.DistinguishedName);
        Assert.Equal(rdn, command.NewRdn);
        Assert.Equal(destinationDn, command.NewSuperior);
        Assert.True(command.DeleteOldRdn);
        Assert.Equal("LDAP://offline.invalid/" + rdn + "," + destinationDn, fixture.Entry.Path);
        Assert.Equal(rdn, fixture.Entry.Name);
        using (var parent = fixture.Entry.Parent) Assert.Equal(destinationDn, parent!.DistinguishedName);
        Assert.Equal(new[] { sourceDn, rdn + "," + destinationDn }, fixture.Buffered.Select(command => command.BaseDn));
        Assert.All(fixture.Buffered, command => Assert.Equal(new[] { "1.1" }, command.Attributes));
        fixture.AssertReleased();
        // DN spelling preservation, not complete RFC4514 parsing, canonical
        // equality, ADSI escaping conventions or server acceptance evidence.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_neutral_rename_or_move_NUL_refuses_before_submission_and_allows_corrected_retry(bool superior)
    {
        using var fixture = new TextBoundaryFixture();
        fixture.Entry.BindEntry();
        var originalPath = fixture.Entry.Path;
        using var malformedParent = new DirectoryEntry("LDAP://offline.invalid/OU=bad\0parent,DC=example");
        fixture.Configure(malformedParent);
        var error = Assert.Throws<ArgumentException>(() =>
        {
            if (superior) fixture.Entry.MoveTo(malformedParent, "CN=after");
            else fixture.Entry.Rename("CN=bad\0rdn");
        });
        Assert.Contains("NUL", error.Message, StringComparison.Ordinal);
        Assert.Empty(fixture.Mutations);
        Assert.Equal(originalPath, fixture.Entry.Path);
        Assert.Single(fixture.Buffered);
        fixture.AssertReleased();
        using var repairedParent = new DirectoryEntry("LDAP://offline.invalid/OU=target,DC=example");
        fixture.Configure(repairedParent);
        if (superior) fixture.Entry.MoveTo(repairedParent, "CN=after");
        else fixture.Entry.Rename("CN=after");
        var command = Assert.Single(fixture.Mutations);
        Assert.Equal("CN=before,OU=source,DC=example", command.DistinguishedName);
        Assert.Equal("CN=after", command.NewRdn);
        Assert.Equal(superior ? "OU=target,DC=example" : "OU=source,DC=example", command.NewSuperior);
        Assert.True(command.DeleteOldRdn);
        Assert.Equal("LDAP://offline.invalid/CN=after," + command.NewSuperior, fixture.Entry.Path);
        fixture.AssertReleased();
        // Public facade acquires a lease before validation. This proves no
        // application mutation dispatch, not no admission/authentication effect.
    }
}
