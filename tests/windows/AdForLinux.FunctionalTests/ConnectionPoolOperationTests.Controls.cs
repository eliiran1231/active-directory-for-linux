using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Public_neutral_control_state_updates_after_structurally_valid_response(bool malformed, bool virtualList)
    {
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        using var root = new AdForLinux.DirectoryServices.DirectoryEntry("LDAP://directory.invalid/DC=example");
        root.Options.Referral = ReferralChasingOption.None;
        var trace = new List<string>();
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
            pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), count, () =>
            {
                var transport = new ConversationTransport(trace);
                transport.Capabilities |= LdapTransportCapabilities.SearchControls;
                var controls = new List<LdapTransportControl> {
                    new("1.2.840.113556.1.4.841", Convert.FromHexString("300A020101020102040200FF"), false),
                    new("2.16.840.1.113730.3.4.10", Convert.FromHexString("300D02010202010A0A0100040200FF"), false) };
                if (malformed) controls.Add(new("2.16.840.1.113730.3.4.10", [255], false));
                transport.Events.Enqueue(new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success) with { Controls = controls.ToArray() }, false));
                return new BoundLdapSession(transport, transport, options, new LdapAuthenticationSource(options), referrals);
            }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
        var sync = new DirectorySynchronization([42]);
        var vlv = new DirectoryVirtualListView(0, 0, 1);
        using var searcher = new AdForLinux.DirectoryServices.DirectorySearcher(root) { DirectorySynchronization = virtualList ? null : sync,
            VirtualListView = virtualList ? vlv : null, ReferralChasing = ReferralChasingOption.None };
        var error = Record.Exception(() => { using var results = searcher.FindAll(); Assert.Empty(results.Cast<SearchResult>()); });
        if (malformed) Assert.IsType<BerConversionException>(error); else Assert.Null(error);
        Assert.Equal(malformed || virtualList ? new byte[] { 42 } : new byte[] { 0, 255 }, sync.GetDirectorySynchronizationCookie());
        Assert.Equal(virtualList && !malformed ? 2 : 1, vlv.Offset);
        Assert.Equal(virtualList && !malformed ? 10 : 0, vlv.ApproximateTotal);
        Assert.Equal(0, pool.Snapshot.Total);
    }

    [Fact]
    public void Public_search_control_recipes_have_managed_BER_vectors()
    {
        Assert.Equal(Convert.FromHexString("3003020101"), LdapControlCodec.FromProtocol(new ExtendedDNControl(ExtendedDNFlag.StandardString)).Value);
        Assert.Equal(Convert.FromHexString("300A020100020100040200FF"), LdapControlCodec.FromProtocol(new DirSyncRequestControl([0, 255], System.DirectoryServices.Protocols.DirectorySynchronizationOptions.None, 0)).Value);
        Assert.Equal(Convert.FromHexString("300930070402636E8101FF"), LdapControlCodec.FromProtocol(new SortRequestControl("cn", true)).Value);
        Assert.Equal(Convert.FromHexString("300E020100020100A006020101020100"), LdapControlCodec.FromProtocol(new VlvRequestControl(0, 0, 1)).Value);
    }

    [Fact]
    public void Neutral_response_state_preserves_cookie_context_and_control_results()
    {
        var state = LdapControlCodec.DecodeResponse([
            new("1.2.840.113556.1.4.841", Convert.FromHexString("300A020101020102040200FF"), false),
            new("2.16.840.1.113730.3.4.10", Convert.FromHexString("300D02010202010A0A0135040200FF"), false),
            new("1.2.840.113556.1.4.474", Convert.FromHexString("30030A0135"), false),
            new("1.2.3", [255], true)]);
        Assert.Equal(new byte[] { 0, 255 }, state.SyncCookie);
        Assert.Equal(2, state.Vlv!.Value.Position); Assert.Equal(10, state.Vlv.Value.Count);
        Assert.Equal(new byte[] { 0, 255 }, state.Vlv.Value.Context);
        Assert.ThrowsAny<Exception>(() => LdapControlCodec.DecodeResponse([
            new("1.2.840.113556.1.4.841", Convert.FromHexString("300A020101020102040200FF00"), false)]));
    }

    [Fact]
    public void Security_control_codec_encodes_public_masks_without_native_BER()
    {
        foreach (var mask in new[] { 0, 1, 4, 15, -1 })
        {
            var control = new SecurityDescriptorFlagControl((System.DirectoryServices.Protocols.SecurityMasks)mask) { IsCritical = false };
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
        NativeLdapBindingBackend.ValidateAbi(4);
        Assert.Throws<PlatformNotSupportedException>(() => NativeLdapBindingBackend.ValidateAbi(3));
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
