using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class ImmediatePasswordFixture : IDisposable
    {
        internal const string Dn = "CN=user,DC=example";
        // Synthetic wire fixtures only: no directory credential or real account.
        internal const string OldValue = "old-test-π🔐", NewValue = "new-test-漢\"quote";
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example");
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid:636/" + Dn, null, null, AuthenticationTypes.SecureSocketsLayer);
        internal readonly UserPrincipal User;
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(1, 1, startTimer: false);
        internal readonly List<ImmediatePasswordTransport> Transports = [];
        internal readonly List<LdapModifyCommand> Invocations = [], Submissions = [];
        internal readonly InvalidOperationException NotSent = new("controlled immediate password failure before submission");
        internal readonly TimeoutException Lost = new("controlled immediate password response loss");
        internal string Outcome = "success", Description = "before";
        internal bool Capable = true;
        internal int Admissions;

        internal ImmediatePasswordFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.PropertyReadOverride = (names, _) =>
            {
                var properties = new PropertyCollection();
                if (names.Length == 0 || names.Contains("objectGUID", StringComparer.OrdinalIgnoreCase))
                    properties.ReplaceLoaded("objectGUID", [new Guid("81c6b89b-3669-4256-8205-10048a3d6a7e").ToByteArray()]);
                if (names.Length == 0 || names.Contains("description", StringComparer.OrdinalIgnoreCase))
                    properties.ReplaceLoaded("description", [Description]);
                return properties;
            };
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            {
                Admissions++;
                Assert.Equal(1, count);
                Assert.True(options.UseSsl);
                Assert.Equal(636, options.Port);
                return Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new ImmediatePasswordTransport(this);
                    Transports.Add(transport);
                    return new BoundLdapSession(transport, transport, options, new(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            };
            User = Assert.IsType<UserPrincipal>(Principal.Materialize(Context, typeof(UserPrincipal), Entry));
            User.Description = "pending scalar";
        }
        internal void Invoke(bool change)
        {
            if (change) User.ChangePassword(OldValue, NewValue);
            else User.SetPassword(NewValue);
        }
        internal void AssertReleased(int expected)
        {
            Assert.Equal(expected, Admissions);
            Assert.Equal(expected, Transports.Count);
            Assert.All(Transports, t => Assert.Equal(1, t.Disposals));
            Assert.Equal(0, Pool.Snapshot.Total);
            Assert.Equal(0, Pool.Snapshot.Waiting);
        }
        public void Dispose() { User.Dispose(); Entry.Dispose(); Context.Dispose(); Pool.Dispose(); }
    }

    private sealed class ImmediatePasswordTransport(ImmediatePasswordFixture fixture)
        : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal int Disposals;
        public LdapTransportCapabilities Capabilities => fixture.Capable ? LdapTransportCapabilities.Modify : LdapTransportCapabilities.None;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => "offline.invalid";
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token)
            => throw new InvalidOperationException("Immediate operation unexpectedly reached a directory read.");
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var modify = Assert.IsType<LdapModifyCommand>(command);
            fixture.Invocations.Add(modify);
            if (fixture.Outcome == "not-sent") throw fixture.NotSent;
            submission.BeforeSend();
            fixture.Submissions.Add(modify);
            if (fixture.Outcome == "rejected")
                return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.ConstraintViolation, null, "controlled policy rejection", [], []));
            if (fixture.Outcome == "lost") throw fixture.Lost;
            foreach (var change in modify.Changes)
                if (change.Name == "description") fixture.Description = Encoding.UTF8.GetString(Assert.Single(change.Values));
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public void Dispose() => Disposals++;
    }

    private static void AssertPasswordWire(LdapModifyCommand command, bool change)
    {
        Assert.Equal(ImmediatePasswordFixture.Dn, command.DistinguishedName);
        Assert.Empty(command.Controls);
        Assert.All(command.Changes, c => Assert.Equal("unicodePwd", c.Name));
        if (change)
        {
            Assert.Equal(2, command.Changes.Length);
            Assert.Equal(DirectoryAttributeOperation.Delete, command.Changes[0].Operation);
            Assert.Equal(Encoding.Unicode.GetBytes("\"" + ImmediatePasswordFixture.OldValue + "\""), Assert.Single(command.Changes[0].Values));
            Assert.Equal(DirectoryAttributeOperation.Add, command.Changes[1].Operation);
            Assert.Equal(Encoding.Unicode.GetBytes("\"" + ImmediatePasswordFixture.NewValue + "\""), Assert.Single(command.Changes[1].Values));
        }
        else
        {
            var reset = Assert.Single(command.Changes);
            Assert.Equal(DirectoryAttributeOperation.Replace, reset.Operation);
            Assert.Equal(Encoding.Unicode.GetBytes("\"" + ImmediatePasswordFixture.NewValue + "\""), Assert.Single(reset.Values));
        }
    }

    [Theory]
    [InlineData(false, "success")]
    [InlineData(true, "success")]
    [InlineData(false, "incapable")]
    [InlineData(true, "incapable")]
    [InlineData(false, "not-sent")]
    [InlineData(true, "not-sent")]
    [InlineData(false, "rejected")]
    [InlineData(true, "rejected")]
    [InlineData(false, "lost")]
    [InlineData(true, "lost")]
    public void Neutral_immediate_password_operations_preserve_wire_shape_pending_edits_and_classified_failures(bool change, string outcome)
    {
        using var fixture = new ImmediatePasswordFixture { Outcome = outcome, Capable = outcome != "incapable" };
        var error = Record.Exception(() => fixture.Invoke(change));
        switch (outcome)
        {
            case "success": Assert.Null(error); break;
            case "incapable": Assert.IsType<PlatformNotSupportedException>(error); break;
            case "not-sent": Assert.Same(fixture.NotSent, error); break;
            case "lost": Assert.Same(fixture.Lost, error); break;
            case "rejected":
                var translated = change ? (Exception)Assert.IsType<PasswordException>(error) : Assert.IsType<InvalidOperationException>(error);
                Assert.Equal((int)ResultCode.ConstraintViolation, Assert.IsType<DirectoryServicesCOMException>(translated.InnerException).ExtendedError);
                break;
        }
        fixture.AssertReleased(1);
        Assert.Equal(outcome == "incapable" ? 0 : 1, fixture.Invocations.Count);
        Assert.Equal(outcome is "incapable" or "not-sent" ? 0 : 1, fixture.Submissions.Count);
        Assert.All(fixture.Invocations, command => AssertPasswordWire(command, change));
        Assert.Equal("pending scalar", fixture.User.Description);
        Assert.Equal("before", fixture.Description);
        if (outcome == "lost") return; // unknown server outcome: no automatic or explicit replay assertion beyond this call

        fixture.Outcome = "success";
        fixture.Capable = true;
        var passwordCalls = 1;
        if (outcome != "success") { fixture.Invoke(change); passwordCalls++; }
        fixture.AssertReleased(passwordCalls);
        Assert.All(fixture.Invocations, command => AssertPasswordWire(command, change));
        var passwordSubmissions = fixture.Submissions.Count;
        fixture.User.Save();
        fixture.AssertReleased(passwordCalls + 1);
        Assert.Equal(passwordSubmissions + 1, fixture.Submissions.Count);
        var scalar = Assert.Single(fixture.Submissions.Last().Changes);
        Assert.Equal("description", scalar.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, scalar.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes("pending scalar"), Assert.Single(scalar.Values));
        Assert.Equal("pending scalar", fixture.Description);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Neutral_password_option_refusal_precedes_admission_and_preserves_explicit_retry(bool change, bool separatePort)
    {
        using var fixture = new ImmediatePasswordFixture();
        if (separatePort) fixture.Entry.Options.PasswordPort = 1636;
        else fixture.Entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingClear;
        Assert.Throws<PlatformNotSupportedException>(() => fixture.Invoke(change));
        fixture.AssertReleased(0);
        Assert.Empty(fixture.Invocations);
        Assert.Empty(fixture.Submissions);
        Assert.Equal("pending scalar", fixture.User.Description);

        fixture.Entry.Options.PasswordPort = 636;
        fixture.Entry.Options.PasswordEncoding = PasswordEncodingMethod.PasswordEncodingSsl;
        fixture.Invoke(change);
        AssertPasswordWire(Assert.Single(fixture.Submissions), change);
        fixture.AssertReleased(1);
    }
}
