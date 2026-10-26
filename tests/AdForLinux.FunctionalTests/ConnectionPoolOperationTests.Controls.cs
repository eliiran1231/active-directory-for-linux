using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Fact]
    public void Security_control_codec_encodes_public_masks_without_native_BER()
    {
        foreach (var mask in new[] { 0, 1, 4, 15, -1 })
        {
            var control = new SecurityDescriptorFlagControl((SecurityMasks)mask) { IsCritical = false };
            var encoded = LdapControlCodec.FromProtocol(control);
            Assert.Equal(new byte[] { 0x30, 3, 2, 1, unchecked((byte)mask) }, encoded.Value);
            Assert.True(encoded.HasValue); Assert.False(encoded.Critical);
        }
        Assert.Equal(new byte[] { 42 }, LdapControlCodec.FromProtocol(new CustomSecurityControl()).Value);
        Assert.False(LdapControlCodec.FromProtocol(new DirectoryControl("1.2.3", [], true, true)).HasValue);
    }
    private sealed class CustomSecurityControl : SecurityDescriptorFlagControl
    { public override byte[] GetValue() => [42]; }

    [Fact]
    public void Control_presence_and_flags_are_preserved_or_rejected_before_dispatch()
    {
        var builder = new NativeSearchResultBuilder();
        builder.Accept(11, null, [], 0);
        builder.Accept(15, "1.2.3", [], 1);
        builder.Accept(15, "1.2.3", [], 2);
        builder.Accept(15, "1.2.3", [0, 255], 3);
        var controls = builder.Complete().Controls;
        Assert.False(controls[0].HasValue); Assert.True(controls[0].Critical);
        Assert.True(controls[1].HasValue); Assert.False(controls[1].Critical);
        Assert.True(controls[2].HasValue); Assert.Equal(new byte[] { 0, 255 }, controls[2].Value);
        Assert.Throws<InvalidOperationException>(() => builder.Accept(15, "1.2.3", [1], 0));
        Assert.Throws<InvalidOperationException>(() => builder.Accept(15, "1.2.3", [], 4));
        Assert.Throws<ArgumentException>(() => LdapControlCodec.Snapshot(new("1.2.3", [1], true, false)));
        NativeLdapBindingBackend.ValidateAbi(3);
        Assert.Throws<PlatformNotSupportedException>(() => NativeLdapBindingBackend.ValidateAbi(1));
        Assert.Throws<PlatformNotSupportedException>(() => NativeLdapBindingBackend.ValidateAbi(2));
    }

    [Fact]
    public void Search_metadata_and_unrepresentable_control_presence_fail_before_dispatch()
    {
        using var transport = new RecordingTransport();
        var request = new SearchRequest("", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base) { RequestId = "opaque" };
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.FromRequest(transport, request, transport.Timeout));
        Assert.Equal(0, transport.Sends);
        var protocols = new ProtocolsLdapTransport(null!); // capability preflight never touches a handle
        var command = new LdapSearchCommand("", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base, [], TimeSpan.FromSeconds(1), Controls: [new("1.2.3", [], true, true)]);
        Assert.Throws<PlatformNotSupportedException>(() => LdapRequestDispatcher.Prepare(protocols, command));
        Assert.False(LdapRequestDispatcher.Prepare(protocols, command with { Controls = [new("1.2.3", [], true, false)] }).Controls![0].HasValue);
    }

    [Fact]
    public void Generic_mutation_control_capability_is_required_and_preserves_snapshots()
    {
        var transport = new GenericMutationTransport();
        var command = new LdapDeleteCommand("CN=test", TimeSpan.FromSeconds(1), [new("1.2.3", [], true, false)]);
        Assert.Throws<PlatformNotSupportedException>(() => LdapMutationCommands.RequireCapabilities(transport, command));
        transport.Capabilities |= LdapTransportCapabilities.MutationControls;
        LdapMutationCommands.RequireCapabilities(transport, command);
        Assert.False(LdapMutationCommands.Prepare(command).Controls[0].HasValue);
    }
}
