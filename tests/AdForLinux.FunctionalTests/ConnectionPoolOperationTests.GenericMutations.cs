using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class GenericMutationTransport : ILdapRequestTransport, ILdapMutationTransport, IDisposable
    {
        internal readonly List<LdapMutationCommand> Commands = [];
        internal bool LoseResponse;
        public LdapTransportCapabilities Capabilities { get; set; } = LdapTransportCapabilities.Add |
            LdapTransportCapabilities.Modify | LdapTransportCapabilities.Delete | LdapTransportCapabilities.ModifyDn;
        public TimeSpan Timeout => TimeSpan.FromSeconds(5);
        public string? ConnectedHost => null;
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken token) => throw new NotSupportedException();
        public ValueTask<LdapResultEnvelope> MutateAsync(LdapMutationCommand command, LdapSubmission submission, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); submission.BeforeSend(); Commands.Add(command);
            if (LoseResponse) throw new TimeoutException("Submitted mutation lost its response.");
            return ValueTask.FromResult(new LdapResultEnvelope(ResultCode.UnwillingToPerform, "CN=matched", "definitive", [], []));
        }
        public void Dispose() { }
    }

    [Fact]
    public async Task Unified_mutations_use_the_same_outcome_coordinator_and_do_not_replay()
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
        var transport = new GenericMutationTransport();
        var options = NativeOwnerOptions();
        LdapConnectionProvider.Session Acquire() => new(pool.Acquire(
            LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None), () =>
                new BoundLdapSession(transport, transport, options, new(options), ReferralChasingOption.None)));
        LdapMutationCommand[] commands =
        [
            new LdapAddCommand("CN=new", [new("description", [[0, 255]])], TimeSpan.FromSeconds(5), []),
            ModifyCommand(), new LdapDeleteCommand("CN=old", TimeSpan.FromSeconds(5), []),
            new LdapModifyDnCommand("CN=old", "CN=renamed", null, false, TimeSpan.FromSeconds(5), [])
        ];
        foreach (var command in commands)
        {
            var outcome = await LdapConversation.Mutate(Acquire, command);
            Assert.Equal(LdapWriteDisposition.Completed, outcome.Disposition);
            Assert.Equal(ResultCode.UnwillingToPerform, outcome.Result!.Code);
            Assert.Null(outcome.Error);
        }
        Assert.Equal(4, transport.Commands.Count);
        transport.LoseResponse = true;
        var unknown = await LdapConversation.Mutate(Acquire, commands[0]);
        Assert.Equal(LdapWriteDisposition.Indeterminate, unknown.Disposition);
        Assert.Equal(5, transport.Commands.Count);
        var cancelled = await LdapConversation.Mutate(Acquire, commands[0], new CancellationToken(true));
        Assert.Equal(LdapWriteDisposition.NotSent, cancelled.Disposition);
        Assert.Equal(5, transport.Commands.Count);
    }

    [Fact]
    public void Unified_dispatch_preserves_attribute_order_binary_values_and_nullable_rename_parent()
    {
        using var transport = new GenericMutationTransport();
        LdapWriteOutcome Send(DirectoryRequest request) => LdapMutationDispatcher.Send(transport, request,
            () => throw new Exception("No Protocols fallback allowed"), () => { });
        var add = new AddRequest("CN=new", new DirectoryAttribute("first", new byte[] { 0, 255 }),
            new DirectoryAttribute("second", Array.Empty<byte>()));
        Assert.Equal(LdapWriteDisposition.Completed, Send(add).Disposition);
        var submitted = Assert.IsType<LdapAddCommand>(transport.Commands[0]);
        Assert.Equal(new[] { "first", "second" }, submitted.Attributes.Select(attribute => attribute.Name));
        Assert.Equal(new byte[] { 0, 255 }, submitted.Attributes[0].Values[0]);
        Assert.Empty(submitted.Attributes[1].Values[0]);
        foreach (var parent in new string?[] { null, "", "OU=other" })
        {
            Assert.Equal(LdapWriteDisposition.Completed, Send(new ModifyDNRequest("CN=old", parent, "CN=renamed") { DeleteOldRdn = false }).Disposition);
            var rename = Assert.IsType<LdapModifyDnCommand>(transport.Commands[^1]);
            Assert.Equal(parent, rename.NewSuperior); Assert.False(rename.DeleteOldRdn);
        }
        Assert.Equal(LdapWriteDisposition.Completed, Send(new DeleteRequest("CN=old")).Disposition);
        Assert.Equal("CN=old", Assert.IsType<LdapDeleteCommand>(transport.Commands[^1]).DistinguishedName);
    }

    [Fact]
    public void Unified_operation_bits_do_not_grant_control_support_or_unsupported_operations()
    {
        using var transport = new GenericMutationTransport();
        var controlled = new DeleteRequest("CN=old"); controlled.Controls.Add(new TreeDeleteControl());
        var result = LdapMutationDispatcher.Send(transport, controlled, () => throw new Exception("No fallback"), () => { });
        Assert.Equal(LdapWriteDisposition.NotSent, result.Disposition);
        Assert.IsType<PlatformNotSupportedException>(result.Error);
        transport.Capabilities = LdapTransportCapabilities.Modify;
        result = LdapMutationDispatcher.Send(transport, new DeleteRequest("CN=old"), () => throw new Exception("No fallback"), () => { });
        Assert.Equal(LdapWriteDisposition.NotSent, result.Disposition);
        Assert.Empty(transport.Commands);
    }
}
