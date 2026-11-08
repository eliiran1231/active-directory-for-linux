using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class PrincipalMutationState
    {
        internal string Outcome = "success";
        internal bool Capable = true;
        internal bool ApplyBeforeResponseLoss;
        internal int Invocations, Submissions, Disposals;
        internal readonly List<LdapModifyCommand> Commands = [];
        internal readonly Dictionary<string, object[]> Server = new(StringComparer.OrdinalIgnoreCase)
        {
            ["objectGUID"] = [new Guid("b191d625-f581-42f7-9f2d-82bbd9ba8cc2").ToByteArray()],
            ["description"] = ["before"],
        };
    }

    private sealed class PrincipalMutationTransport(PrincipalMutationState state) : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        public LdapTransportCapabilities Capabilities => state.Capable ? LdapTransportCapabilities.Modify : LdapTransportCapabilities.None;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Unexpected search outside controlled property reader.");
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken cancellationToken)
        {
            state.Invocations++;
            if (state.Outcome == "not-sent") throw new InvalidOperationException("controlled failure before submission");
            submission.BeforeSend();
            state.Submissions++;
            var modify = Assert.IsType<LdapModifyCommand>(command);
            state.Commands.Add(modify);
            if (state.Outcome == "rejected")
                return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.InsufficientAccessRights, null, "controlled rejection", [], []));
            if (state.Outcome != "lost" || state.ApplyBeforeResponseLoss)
                foreach (var change in modify.Changes)
                {
                    Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
                    state.Server[change.Name] = change.Values.Select(value => (object)Encoding.UTF8.GetString(value)).ToArray();
                }
            if (state.Outcome == "lost") throw new TimeoutException("controlled failure after submission");
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.Success, null, null, [], []));
        }
        public void Dispose() => state.Disposals++;
    }

    private sealed class NeutralPrincipalSaveFixture : IDisposable
    {
        internal readonly PrincipalMutationState State = new();
        internal readonly PrincipalContext Context = new(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        internal readonly DirectoryEntry Entry = new("LDAP://offline.invalid/CN=item,DC=example,DC=test");
        internal readonly UserPrincipal User;
        private readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool = new(1, 1, startTimer: false);
        internal NeutralPrincipalSaveFixture()
        {
            Entry.PropertyReadOverride = (names, _) =>
            {
                var properties = new PropertyCollection();
                foreach (var pair in State.Server)
                    if (names.Length == 0 || names.Contains(pair.Key, StringComparer.OrdinalIgnoreCase))
                        properties.ReplaceLoaded(pair.Key, pair.Value);
                return properties;
            };
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new PrincipalMutationTransport(State);
                    return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
            User = Assert.IsType<UserPrincipal>(Principal.Materialize(Context, typeof(UserPrincipal), Entry));
        }
        public void Dispose() { User.Dispose(); Entry.Dispose(); Context.Dispose(); pool.Dispose(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_principal_save_retains_retryable_edit_after_capability_or_presubmission_failure(bool incapable)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.User.Description = "requested";
        fixture.State.Capable = !incapable;
        fixture.State.Outcome = "not-sent";
        if (incapable) Assert.Throws<PlatformNotSupportedException>(fixture.User.Save);
        else Assert.Throws<InvalidOperationException>(fixture.User.Save);
        Assert.Equal(incapable ? 0 : 1, fixture.State.Invocations);
        Assert.Equal(0, fixture.State.Submissions);
        Assert.Equal("before", Assert.Single(fixture.State.Server["description"]));

        fixture.State.Capable = true;
        fixture.State.Outcome = "success";
        fixture.User.Save();
        Assert.Equal(1, fixture.State.Submissions);
        Assert.Equal(incapable ? 1 : 2, fixture.State.Invocations);
        Assert.Equal("requested", Assert.Single(fixture.State.Server["description"]));
        Assert.Equal(2, fixture.State.Disposals);
        Assert.Equal("CN=item,DC=example,DC=test", Assert.Single(fixture.State.Commands).DistinguishedName);
    }

    [Fact]
    public void Public_principal_save_definitive_neutral_rejection_does_not_quarantine_retry()
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.User.Description = "requested";
        fixture.State.Outcome = "rejected";
        Assert.Throws<UnauthorizedAccessException>(fixture.User.Save);
        Assert.Equal(1, fixture.State.Submissions);
        Assert.Equal("before", Assert.Single(fixture.State.Server["description"]));
        fixture.State.Outcome = "success";
        fixture.User.Save();
        Assert.Equal(2, fixture.State.Invocations);
        Assert.Equal(2, fixture.State.Submissions);
        Assert.Equal("requested", Assert.Single(fixture.State.Server["description"]));
        Assert.Equal(2, fixture.State.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scalar_readback_must_prevent_replay_on_later_unrelated_save_regression(bool applied)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.User.Description = "requested";
        fixture.State.Outcome = "lost";
        fixture.State.ApplyBeforeResponseLoss = applied;
        Assert.Throws<TimeoutException>(fixture.User.Save);
        Assert.Equal(1, fixture.State.Submissions);
        Assert.Equal(1, fixture.State.Disposals);
        fixture.State.Outcome = "success";
        fixture.Entry.RefreshCache(["description"]);
        Assert.Equal(applied ? "requested" : "before", fixture.Entry.Properties["description"].Value);
        fixture.User.DisplayName = "later edit";
        fixture.User.Save();
        Assert.Equal(2, fixture.State.Submissions);
        Assert.Equal(applied ? "requested" : "before", Assert.Single(fixture.State.Server["description"]));
        Assert.Equal("later edit", Assert.Single(fixture.State.Server["displayName"]));
        Assert.Equal("displayName", Assert.Single(fixture.State.Commands[1].Changes).Name);
        Assert.Equal(2, fixture.State.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Blocked_save_retry_must_not_make_unchanged_scalar_readback_impossible_regression(bool applied)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.User.Description = "requested";
        fixture.State.Outcome = "lost";
        fixture.State.ApplyBeforeResponseLoss = applied;
        Assert.Throws<TimeoutException>(fixture.User.Save);
        fixture.State.Outcome = "success";
        Assert.Throws<InvalidOperationException>(fixture.User.Save);
        Assert.Equal(1, fixture.State.Invocations);
        Assert.Equal(1, fixture.State.Submissions);
        // No caller edits followed the first request. A refused retry must leave
        // the same explicit readback recovery available as before that retry.
        fixture.Entry.RefreshCache(["description"]);
        Assert.Equal(applied ? "requested" : "before", fixture.Entry.Properties["description"].Value);
        Assert.Equal(1, fixture.State.Submissions);
    }
}
