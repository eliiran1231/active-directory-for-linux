#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private const EntryMasks AllEntrySections = EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl;
    private sealed class EntryWriteFixture : IDisposable
    {
        internal readonly DirectoryEntry Entry = new("LDAP://dc.example/CN=item,DC=example,DC=com");
        internal byte[] Raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)));
        internal readonly List<DirectoryRequest> Writes = new();
        internal EntryWriteFixture()
        {
            Entry.Options.SecurityMasks = AllEntrySections;
            Entry.SecurityReadOverride = _ => (byte[])Raw.Clone();
            Entry.PropertyReadOverride = (_, _) => new PropertyCollection();
            Entry.WriteRequestOverride = request =>
            {
                Assert.False(Monitor.IsEntered(A.FacadeMutation.Gate));
                Writes.Add(request); return ResultCode.Success;
            };
        }
        public void Dispose() => Entry.Dispose();
    }

    [Fact]
    public void Entry_commit_combines_properties_with_only_raw_edited_security_sections()
    {
        using var fixture = new EntryWriteFixture();
        var entry = fixture.Entry; var security = entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        var expected = security._securityDescriptor.MutationState.Descriptor.GetBinaryForm();
        entry.Properties["description"].Value = "changed";
        entry.ObjectSecurity = security;
        Assert.Same(security, entry.ObjectSecurity);
        entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal("CN=item,DC=example,DC=com", request.DistinguishedName);
        Assert.Equal(2, request.Modifications.Count);
        Assert.Equal(System.DirectoryServices.Protocols.SecurityMasks.Owner,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
        var descriptor = request.Modifications.Cast<DirectoryAttributeModification>().Single(m => m.Name == "nTSecurityDescriptor");
        Assert.Equal(expected, Assert.IsType<byte[]>(descriptor[0]));
        Assert.NotSame(security, entry.ObjectSecurity);
    }

    [Fact]
    public void Entry_clean_or_reverted_security_commit_sends_nothing()
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        fixture.Entry.CommitChanges();
        Assert.NotSame(security, fixture.Entry.ObjectSecurity);
        security = fixture.Entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        security.SetOwner(new SecurityIdentifier(U1, 0));
        fixture.Entry.CommitChanges();
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Entry_owner_write_preserves_unrelated_raw_aces_even_when_projection_differs()
    {
        using var fixture = new EntryWriteFixture();
        var acl = Acl(4, Ace(0, 0, 0, U1), Ace(9, 0, 16, U1, new byte[] { 1, 2, 3, 4 }));
        fixture.Raw = Build(U1, U1, acl);
        var security = fixture.Entry.ObjectSecurity;
        Assert.NotEqual(fixture.Raw, security.GetSecurityDescriptorBinaryForm());
        security.SetOwner(new SecurityIdentifier(U2, 0));
        fixture.Entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal(Build(U2, U1, acl), Assert.IsType<byte[]>(Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>())[0]));
    }

    [Fact]
    public void Entry_assignment_preserves_pending_destination_sections()
    {
        using var fixture = new EntryWriteFixture();
        var destination = fixture.Entry.ObjectSecurity;
        destination.SetGroup(new SecurityIdentifier(U2, 0));
        var source = new ActiveDirectorySecurity(Build(U1, U1, Acl(4)), AllEntrySections);
        source.SetOwner(new SecurityIdentifier(U2, 0));
        fixture.Entry.ObjectSecurity = source;
        var assigned = fixture.Entry.ObjectSecurity;
        Assert.Equal(EntryMasks.Owner | EntryMasks.Group, assigned.PendingWriteSections);
        Assert.Equal(new SecurityIdentifier(U2, 0), assigned.GetGroup(typeof(SecurityIdentifier)));
        fixture.Entry.CommitChanges();
        Assert.Single(fixture.Writes);
    }

    [Fact]
    public async Task Entry_blocked_transport_allows_peer_edits_and_rejects_concurrent_commit()
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        fixture.Entry.WriteRequestOverride = _ =>
        { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10))); return ResultCode.Success; };
        var commit = Task.Run(() => Record.Exception(fixture.Entry.CommitChanges));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            var edit = Task.Run(() => security.SetGroup(new SecurityIdentifier(U2, 0)));
            await edit.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Throws<InvalidOperationException>(fixture.Entry.CommitChanges);
        }
        finally { release.Set(); }
        Assert.IsType<InvalidOperationException>(await commit.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(EntryMasks.Owner | EntryMasks.Group, security.PendingWriteSections);
    }

    [Fact]
    public void Entry_detached_assignment_copies_selected_data_and_destination_authority()
    {
        using var source = new EntryWriteFixture(); using var destination = new EntryWriteFixture();
        var input = source.Entry.ObjectSecurity;
        input.SetOwner(new SecurityIdentifier(U2, 0));
        var target = destination.Entry.ObjectSecurity;
        destination.Entry.ObjectSecurity = input;
        var assigned = destination.Entry.ObjectSecurity;
        Assert.NotSame(input, assigned); Assert.NotSame(target, assigned);
        Assert.Equal(target.RawReadOrigin, assigned.RawReadOrigin);
        Assert.NotEqual(input.RawReadOrigin, assigned.RawReadOrigin);
        source.Dispose();
        input.SetGroup(new SecurityIdentifier(U2, 0));
        Assert.Equal(new SecurityIdentifier(U1, 0), assigned.GetGroup(typeof(SecurityIdentifier)));
        destination.Entry.CommitChanges();
        Assert.Single(destination.Writes); Assert.Empty(source.Writes);
    }

    [Fact]
    public void Entry_detached_assignment_without_intent_or_unread_sections_refuses_atomically()
    {
        using var fixture = new EntryWriteFixture();
        fixture.Entry.Options.SecurityMasks = EntryMasks.Dacl;
        var baseline = fixture.Entry.ObjectSecurity;
        var detached = new ActiveDirectorySecurity(Build(U1, U1, Acl(4)), AllEntrySections);
        Assert.Throws<InvalidOperationException>(() => fixture.Entry.ObjectSecurity = detached);
        detached.SetOwner(new SecurityIdentifier(U2, 0));
        Assert.Throws<InvalidOperationException>(() => fixture.Entry.ObjectSecurity = detached);
        Assert.Same(baseline, fixture.Entry.ObjectSecurity); Assert.Empty(fixture.Writes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_cache_off_assignment_and_property_writes_use_same_planner(bool securityWrite)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Entry.UsePropertyCache = false;
        if (securityWrite)
        {
            var security = fixture.Entry.ObjectSecurity;
            security.SetOwner(new SecurityIdentifier(U2, 0));
            fixture.Entry.ObjectSecurity = security;
        }
        else fixture.Entry.Properties["description"].Value = "changed";
        Assert.Single(fixture.Writes);
    }

    [Fact]
    public void Entry_failed_send_keeps_pending_state_for_retry()
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        fixture.Entry.Properties["description"].Value = "changed";
        fixture.Entry.WriteRequestOverride = _ => ResultCode.UnwillingToPerform;
        Assert.NotNull(Record.Exception(fixture.Entry.CommitChanges));
        Assert.Same(security, fixture.Entry.ObjectSecurity);
        fixture.Entry.WriteRequestOverride = request => { fixture.Writes.Add(request); return ResultCode.Success; };
        fixture.Entry.CommitChanges();
        Assert.Equal(2, Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)).Modifications.Count);
    }

    [Fact]
    public void Entry_missing_response_requires_readback_before_retry_without_clearing_intent()
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        fixture.Entry.WriteRequestOverride = _ => throw new TimeoutException("controlled missing response");
        Assert.Throws<TimeoutException>(fixture.Entry.CommitChanges);
        Assert.Same(security, fixture.Entry.ObjectSecurity);
        Assert.Equal(EntryMasks.Owner, security.PendingWriteSections);
        Assert.Throws<InvalidOperationException>(fixture.Entry.CommitChanges);
        fixture.Entry.RefreshCache();
        fixture.Entry.CommitChanges();
    }

    [Theory]
    [InlineData("property")] [InlineData("security")] [InlineData("refresh")]
    [InlineData("path")] [InlineData("close")] [InlineData("dispose")]
    public void Entry_send_races_never_publish_stale_success(string change)
    {
        using var fixture = new EntryWriteFixture();
        var entry = fixture.Entry; var security = entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        var property = entry.Properties["description"]; property.Value = "sent";
        entry.WriteRequestOverride = request =>
        {
            fixture.Writes.Add(request);
            switch (change)
            {
                case "property": property.Value = "later"; break;
                case "security": security.SetGroup(new SecurityIdentifier(U2, 0)); break;
                case "refresh": entry.RefreshCache(); break;
                case "path": entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
                case "close": entry.Close(); break;
                case "dispose": entry.Dispose(); break;
            }
            return ResultCode.Success;
        };
        Assert.NotNull(Record.Exception(entry.CommitChanges));
        Assert.Single(fixture.Writes);
        if (change == "dispose") return;
        Assert.Throws<InvalidOperationException>(entry.CommitChanges);
        if (change == "property") { Assert.Equal("later", property.Value); Assert.True(property.Changed); }
        if (change == "security") Assert.Equal(AllEntrySections & (EntryMasks.Owner | EntryMasks.Group), security.PendingWriteSections);
        // A successful response racing with local changes is not permission to
        // discard unsent edits or reconcile a different binding automatically.
        Assert.Throws<InvalidOperationException>(entry.RefreshCache);
        Assert.Single(fixture.Writes);
    }

    [Theory]
    [InlineData("path")] [InlineData("close")] [InlineData("dispose")]
    public void Entry_raw_read_races_do_not_attach_stale_descriptors(string change)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Entry.SecurityReadOverride = _ =>
        {
            switch (change)
            {
                case "path": fixture.Entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
                case "close": fixture.Entry.Close(); break;
                case "dispose": fixture.Entry.Dispose(); break;
            }
            return fixture.Raw;
        };
        Assert.NotNull(Record.Exception(() => fixture.Entry.ObjectSecurity));
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Entry_refresh_refuses_to_discard_edits_made_while_reading()
    {
        using var fixture = new EntryWriteFixture();
        var security = fixture.Entry.ObjectSecurity;
        fixture.Entry.PropertyReadOverride = (_, _) =>
        { security.SetOwner(new SecurityIdentifier(U2, 0)); return new PropertyCollection(); };
        Assert.Throws<InvalidOperationException>(fixture.Entry.RefreshCache);
        Assert.Same(security, fixture.Entry.ObjectSecurity);
        Assert.Equal(EntryMasks.Owner, security.PendingWriteSections);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_add_omits_default_descriptor_or_sends_complete_protected_raw_input(bool explicitDescriptor)
    {
        using var fixture = new EntryWriteFixture();
        using var child = DirectoryEntry.NewChild(fixture.Entry, "CN=child", "user");
        child.WriteRequestOverride = request => { fixture.Writes.Add(request); return ResultCode.Success; };
        var raw = Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000);
        if (explicitDescriptor) child.ObjectSecurity = new ActiveDirectorySecurity(raw, AllEntrySections);
        child.CommitChanges();
        var request = Assert.IsType<AddRequest>(Assert.Single(fixture.Writes));
        Assert.Empty(request.Controls);
        var descriptors = request.Attributes.Cast<DirectoryAttribute>().Where(a => a.Name == "nTSecurityDescriptor").ToArray();
        if (explicitDescriptor) Assert.Equal(raw, Assert.IsType<byte[]>(Assert.Single(descriptors)[0]));
        else Assert.Empty(descriptors);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_add_refuses_incomplete_or_inheriting_descriptor_without_publication(bool incomplete)
    {
        using var fixture = new EntryWriteFixture();
        using var child = DirectoryEntry.NewChild(fixture.Entry, "CN=child", "user");
        var raw = Build(U1, U1, Acl(4), Acl(4), extraControl: incomplete ? (ushort)0x3000 : (ushort)0);
        var source = new ActiveDirectorySecurity(raw, incomplete ? EntryMasks.Dacl : AllEntrySections);
        Assert.Throws<NotSupportedException>(() => child.ObjectSecurity = source);
        child.WriteRequestOverride = request => { fixture.Writes.Add(request); return ResultCode.Success; };
        child.CommitChanges();
        Assert.DoesNotContain(Assert.IsType<AddRequest>(Assert.Single(fixture.Writes)).Attributes.Cast<DirectoryAttribute>(),
            attribute => attribute.Name == "nTSecurityDescriptor");
    }

    [Fact]
    public void Entry_raw_property_descriptor_bypass_refuses_before_sending()
    {
        using var fixture = new EntryWriteFixture();
        fixture.Entry.Properties["nTSecurityDescriptor"].Value = fixture.Raw;
        Assert.Throws<InvalidOperationException>(fixture.Entry.CommitChanges);
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Entry_backed_principal_sid_returns_detached_portable_value()
    {
        using var fixture = new EntryWriteFixture();
        var bytes = (byte[])U1.Clone();
        fixture.Entry.PropertyReadOverride = (_, _) =>
        {
            var properties = new PropertyCollection();
            properties.ReplaceLoaded("objectSid", new object[] { bytes });
            properties.ReplaceLoaded("objectGUID", new object[] { G1.ToByteArray() });
            return properties;
        };
        using var context = new AdForLinux.DirectoryServices.AccountManagement.PrincipalContext(
            AdForLinux.DirectoryServices.AccountManagement.ContextType.Domain, "dc.example");
        using var principal = new AdForLinux.DirectoryServices.AccountManagement.UserPrincipal(context, fixture.Entry);
        var sid = Assert.IsType<SecurityIdentifier>(principal.Sid);
        Assert.Equal(new SecurityIdentifier(U1, 0), sid);
        bytes[^1] ^= 1;
        Assert.Equal(new SecurityIdentifier(U1, 0), sid);
        Assert.Empty(fixture.Writes);
    }
}
