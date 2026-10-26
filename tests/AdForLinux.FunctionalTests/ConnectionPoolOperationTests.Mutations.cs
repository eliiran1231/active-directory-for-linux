using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Entry = AdForLinux.DirectoryServices.DirectoryEntry;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class MutationState
    {
        internal LdapTransportCapabilities Capabilities = LdapTransportCapabilities.Modify;
        internal int Sends;
        internal int Reads;
        internal Func<LdapSearchCommand, LdapSearchResult>? Read;
        internal bool LoseResponse;
        internal ResultCode Result = ResultCode.Success;
        internal LdapModifyCommand? Last;
    }

    private sealed class MutationTransport(MutationState state) : ILdapConversationTransport, IDisposable
    {
        public LdapTransportCapabilities Capabilities => state.Capabilities;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
        { state.Reads++; return state.Read?.Invoke(command) ?? throw new NotSupportedException(); }
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken cancellationToken)
        {
            submission.BeforeSend(); state.Sends++; state.Last = command;
            if (state.LoseResponse) throw new TimeoutException("Recording response was lost after submission.");
            return ValueTask.FromResult(new LdapResultEnvelope(state.Result, "CN=matched", "recording result", [], []));
        }
        public void Dispose() { }
    }

    private sealed class MutationFixture : IDisposable
    {
        internal readonly MutationState State = new();
        internal readonly BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> Pool = new(2, 2, startTimer: false);
        internal readonly Entry Entry = new("LDAP://directory.invalid/CN=example", "reader", "synthetic", AuthenticationTypes.None);
        internal MutationFixture()
        {
            Entry.Options.Referral = ReferralChasingOption.None;
            Entry.PropertyReadOverride = (_, _) =>
            {
                var properties = new PropertyCollection();
                properties.ReplaceLoaded("description", ["before"]);
                return properties;
            };
            Entry.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
                Pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
                {
                    var transport = new MutationTransport(State);
                    return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
                }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        }
        public void Dispose() { Entry.Dispose(); Pool.Dispose(); }
    }

    [Fact]
    public void Public_property_refresh_and_commit_use_neutral_requests_without_read_override()
    {
        using var fixture = new MutationFixture();
        fixture.Entry.PropertyReadOverride = null;
        fixture.State.Capabilities |= LdapTransportCapabilities.Search;
        fixture.State.Read = command => new(ResultCode.Success, "", null, command.BaseDn == "" ? [] :
            [TransportRow(command.BaseDn, new() { ["description"] = ["before"] })], [], [], []);
        fixture.Entry.RefreshCache(["description"]);
        Assert.Equal("before", fixture.Entry.Properties["description"].Value);
        fixture.Entry.Properties["description"].Value = "after";
        fixture.Entry.CommitChanges();
        Assert.Equal(2, fixture.State.Reads); // property result then schema lookup on idle session
        Assert.Equal(1, fixture.State.Sends);
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes("after"), Assert.Single(Assert.Single(fixture.State.Last!.Changes).Values));
        // Default reads request security masks; unsupported controls are not dropped.
        Assert.Throws<PlatformNotSupportedException>(() => fixture.Entry.RefreshCache());
        Assert.Equal(2, fixture.State.Reads);
    }

    [Fact]
    public void Public_commit_unsent_capability_failure_retains_retryable_intent()
    {
        using var fixture = new MutationFixture();
        fixture.Entry.Properties["description"].Value = "after";
        fixture.State.Capabilities = LdapTransportCapabilities.None;
        Assert.Throws<PlatformNotSupportedException>(() => fixture.Entry.CommitChanges());
        Assert.Equal(0, fixture.State.Sends);
        fixture.State.Capabilities = LdapTransportCapabilities.Modify;
        fixture.Entry.CommitChanges();
        Assert.Equal(1, fixture.State.Sends);
        var change = Assert.Single(fixture.State.Last!.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes("after"), Assert.Single(change.Values));
    }

    [Fact]
    public void Public_commit_definitive_rejection_is_retryable_but_missing_response_is_not()
    {
        using var fixture = new MutationFixture();
        fixture.Entry.Properties["description"].Value = "after";
        fixture.State.Result = ResultCode.InsufficientAccessRights;
        var error = Assert.Throws<DirectoryServicesCOMException>(() => fixture.Entry.CommitChanges());
        Assert.Equal((int)ResultCode.InsufficientAccessRights, error.ExtendedError);
        fixture.State.Result = ResultCode.Success;
        fixture.State.LoseResponse = true;
        Assert.Throws<TimeoutException>(() => fixture.Entry.CommitChanges());
        Assert.Equal(2, fixture.State.Sends);
        fixture.State.LoseResponse = false;
        Assert.Throws<InvalidOperationException>(() => fixture.Entry.CommitChanges());
        Assert.Equal(2, fixture.State.Sends); // the ambiguous write is never replayed
    }

    [Fact]
    public void Neutral_mutation_preflight_preserves_all_controls_and_rejects_unsupported_request_types()
    {
        using var fixture = new MutationFixture();
        using var lease = fixture.Entry.AcquireConnection();
        DirectoryRequest[] unsupported = [new AddRequest("CN=new"), new DeleteRequest("CN=old"), new ModifyDNRequest("CN=old", "DC=example", "CN=new")];
        foreach (var request in unsupported)
        {
            var outcome = lease.SendWrite(request);
            Assert.Equal(LdapWriteDisposition.NotSent, outcome.Disposition);
            Assert.IsType<PlatformNotSupportedException>(outcome.Error);
        }
        var modify = new ModifyRequest("CN=example", DirectoryAttributeOperation.Replace, "description", "after");
        modify.Controls.Add(new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl));
        Assert.Equal(LdapWriteDisposition.NotSent, lease.SendWrite(modify).Disposition);
        Assert.Throws<PlatformNotSupportedException>(() => fixture.Entry.DeleteTree());
        Assert.Equal(0, fixture.State.Sends);
    }

    [Fact]
    public void Neutral_modify_preserves_binary_zero_length_and_empty_value_list()
    {
        using var fixture = new MutationFixture();
        using var lease = fixture.Entry.AcquireConnection();
        var request = new ModifyRequest("CN=example");
        var replacement = new DirectoryAttributeModification { Name = "binary", Operation = DirectoryAttributeOperation.Replace };
        replacement.Add(new byte[] { 0, 255 }); replacement.Add(Array.Empty<byte>());
        request.Modifications.Add(replacement);
        request.Modifications.Add(new DirectoryAttributeModification { Name = "other", Operation = DirectoryAttributeOperation.Delete });
        Assert.Equal(LdapWriteDisposition.Completed, lease.SendWrite(request).Disposition);
        Assert.Equal(new byte[] { 0, 255 }, fixture.State.Last!.Changes[0].Values[0]);
        Assert.Empty(fixture.State.Last.Changes[0].Values[1]);
        Assert.Empty(fixture.State.Last.Changes[1].Values);
    }

    [Fact]
    public void Protocols_mutation_retains_original_request_and_definitive_exception()
    {
        var request = new DeleteRequest("CN=example");
        request.Controls.Add(new TreeDeleteControl());
        var original = new DirectoryOperationException(Response("", [], ResultCode.InsufficientAccessRights));
        using var connection = Connection.Create(sent => { Assert.Same(request, sent); throw original; });
        using var lease = new Entry.ConnectionLease(connection);
        var outcome = lease.SendWrite(request);
        Assert.Equal(LdapWriteDisposition.Completed, outcome.Disposition);
        Assert.Same(original, outcome.Error);
        var translated = Assert.Throws<DirectoryServicesCOMException>(() => lease.SendWriteCompatible(request));
        Assert.Same(original, translated.InnerException);
    }
}
