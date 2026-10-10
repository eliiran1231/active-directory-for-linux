using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_uncertain_modify_requires_readback_of_every_sent_attribute(bool combined)
    {
        using var fixture = new EntryWriteFixture();
        var entry = fixture.Entry;
        var member = entry.Properties["member"];
        member.Add("CN=accepted,DC=example,DC=com");
        if (combined) entry.ObjectSecurity.SetOwner(new SecurityIdentifier(U2, 0));
        var serverMembers = new List<string>();
        entry.WriteRequestOverride = request =>
        {
            fixture.Writes.Add(request);
            foreach (var modification in Assert.IsType<ModifyRequest>(request).Modifications.Cast<DirectoryAttributeModification>())
            {
                if (modification.Name == "member") serverMembers.Add((string)modification[0]);
                else if (modification.Name == "nTSecurityDescriptor") fixture.Raw = (byte[])modification[0];
            }
            throw new TimeoutException("Server accepted the write; response was lost.");
        };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        entry.PropertyReadOverride = (names, _) =>
        {
            var result = new PropertyCollection();
            if (names.Contains("*") || names.Contains("member")) result.ReplaceLoaded("member", serverMembers.Cast<object>());
            if (names.Contains("nTSecurityDescriptor")) result.ReplaceLoaded("nTSecurityDescriptor", new object[] { fixture.Raw });
            return result;
        };
        entry.RefreshCache(new[] { "nTSecurityDescriptor" });
        Assert.Throws<InvalidOperationException>(entry.CommitChanges);
        Assert.Single(serverMembers); Assert.Single(fixture.Writes);
        entry.RefreshCache();
        entry.CommitChanges();
        Assert.Single(serverMembers); Assert.Single(fixture.Writes);
        // Retained wrappers must not carry an acknowledged Add into a later edit.
        Assert.False(member.Changed);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Entry_uncertain_creation_never_adopts_same_dn_or_replays_add_after_readback(bool matchingAttributes, bool explicitDescriptor)
    {
        using var fixture = new EntryWriteFixture();
        using var child = DirectoryEntry.NewChild(fixture.Entry, "CN=child", "user");
        var raw = Build(U1, U1, Acl(4), Acl(4), extraControl: 0x3000);
        if (explicitDescriptor) child.ObjectSecurity = new ActiveDirectorySecurity(raw, AllEntrySections);
        var assigned = explicitDescriptor ? child.ObjectSecurity : null;
        var adds = 0;
        child.WriteRequestOverride = request =>
        { Assert.IsType<AddRequest>(request); adds++; throw new TimeoutException("Accepted Add, lost response."); };
        Assert.Throws<TimeoutException>(child.CommitChanges);
        var reads = 0;
        child.PropertyReadOverride = (_, _) =>
        {
            reads++;
            var result = new PropertyCollection();
            result.ReplaceLoaded("objectGUID", new object[] { G1.ToByteArray() });
            result.ReplaceLoaded("objectClass", new object[] { matchingAttributes ? "user" : "group" });
            return result;
        };
        // Even matching attributes and a newly observed GUID cannot identify which
        // actor created the object. This handle must remain quarantined.
        Assert.Throws<InvalidOperationException>(child.RefreshCache);
        Assert.Throws<InvalidOperationException>(child.CommitChanges);
        Assert.Equal(1, adds);
        Assert.True(reads <= 1);
        Assert.True(child.Properties["objectClass"].Changed);
        if (explicitDescriptor)
        {
            Assert.Same(assigned, child.ObjectSecurity);
            Assert.Equal(raw, assigned!._securityDescriptor.MutationState.Descriptor.GetBinaryForm());
        }
    }

    [Fact]
    public void Entry_uncertain_modify_readback_does_not_discard_later_unsent_edits()
    {
        using var fixture = new EntryWriteFixture();
        var entry = fixture.Entry;
        var member = entry.Properties["member"]; member.Add("sent");
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); throw new TimeoutException(); };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        member.Add("unsent");
        Assert.Throws<InvalidOperationException>(entry.RefreshCache);
        Assert.True(member.Changed); Assert.Equal(new object?[] { "sent", "unsent" }, member.ToArray());
        Assert.Throws<InvalidOperationException>(entry.CommitChanges);
        Assert.Single(fixture.Writes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_uncertain_combined_modify_requires_security_mask_coverage_and_successful_read(bool failRead)
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        var member = entry.Properties["member"]; member.Add("accepted");
        entry.ObjectSecurity.SetOwner(new SecurityIdentifier(U2, 0));
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); throw new TimeoutException(); };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        entry.Options.SecurityMasks = AdForLinux.DirectoryServices.SecurityMasks.Dacl;
        if (failRead)
        {
            entry.PropertyReadOverride = (_, _) => throw new TimeoutException("read failed");
            Assert.Throws<TimeoutException>(entry.RefreshCache);
        }
        else Assert.Throws<InvalidOperationException>(entry.RefreshCache);
        Assert.Throws<InvalidOperationException>(entry.CommitChanges);
        Assert.True(member.Changed);
        entry.Options.SecurityMasks = AllEntrySections;
        entry.PropertyReadOverride = (_, _) =>
        {
            var result = new PropertyCollection();
            result.ReplaceLoaded("nTSecurityDescriptor", new object[] { fixture.Raw });
            return result;
        };
        entry.RefreshCache(); entry.CommitChanges();
        Assert.Single(fixture.Writes); Assert.False(member.Changed);
    }

    [Fact]
    public void Entry_uncertain_modify_can_reconcile_exact_attribute_set_without_dropping_unrelated_pending_edits()
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        var member = entry.Properties["member"]; member.Add("accepted");
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); throw new TimeoutException(); };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        var description = entry.Properties["description"]; description.Value = "unsent";
        entry.RefreshCache(new[] { "member" });
        Assert.True(description.Changed); Assert.False(member.Changed);
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); return ResultCode.Success; };
        entry.CommitChanges();
        var second = Assert.IsType<ModifyRequest>(fixture.Writes[1]);
        Assert.Equal("description", Assert.Single(second.Modifications.Cast<DirectoryAttributeModification>()).Name);
        Assert.Equal(2, fixture.Writes.Count);
    }

    [Theory]
    [InlineData("omitted", false)] [InlineData("omitted", true)]
    [InlineData("null", false)] [InlineData("null", true)]
    [InlineData("text", false)] [InlineData("text", true)]
    [InlineData("malformed", false)] [InlineData("malformed", true)]
    [InlineData("multiple", false)] [InlineData("multiple", true)]
    [InlineData("coverage", false)] [InlineData("coverage", true)]
    public void Entry_uncertain_security_readback_refuses_invalid_data_without_publishing(string failure, bool full)
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        var properties = entry.Properties;
        var member = properties["member"]; member.Add("sent");
        var security = entry.ObjectSecurity;
        security.SetOwner(new SecurityIdentifier(U2, 0));
        var raw = security._securityDescriptor.MutationState.Descriptor.GetBinaryForm();
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); throw new TimeoutException(); };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        if (failure == "coverage") entry.Options.SecurityMasks = AdForLinux.DirectoryServices.SecurityMasks.Dacl;
        entry.PropertyReadOverride = (_, _) =>
        {
            var result = new PropertyCollection();
            result.ReplaceLoaded("member", new object[] { "readback" });
            if (failure != "omitted") result.ReplaceLoaded("nTSecurityDescriptor", failure switch
            {
                "null" => new object[] { null! },
                "text" => new object[] { "O:SY" },
                "malformed" => new object[] { new byte[] { 1, 0, 0, 128 } },
                "multiple" => new object[] { fixture.Raw, fixture.Raw },
                _ => new object[] { fixture.Raw }
            });
            return result;
        };
        for (var attempt = 0; attempt < 2; attempt++)
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                if (full) entry.RefreshCache();
                else entry.RefreshCache(new[] { "member", "nTSecurityDescriptor" });
            });
            Assert.Same(properties, entry.Properties); Assert.Same(security, entry.ObjectSecurity);
            Assert.Equal(raw, security._securityDescriptor.MutationState.Descriptor.GetBinaryForm());
            Assert.Equal(AdForLinux.DirectoryServices.SecurityMasks.Owner, security.PendingWriteSections);
            Assert.True(member.Changed); Assert.Equal("sent", member.Value);
            Assert.Throws<InvalidOperationException>(entry.CommitChanges);
        }
        Assert.Single(fixture.Writes);
        // A later real binary read can reconcile; failed attempts did not destroy intent.
        entry.Options.SecurityMasks = AllEntrySections;
        entry.PropertyReadOverride = (_, _) =>
        {
            var result = new PropertyCollection();
            result.ReplaceLoaded("nTSecurityDescriptor", new object[] { fixture.Raw });
            return result;
        };
        entry.RefreshCache(); entry.CommitChanges();
        Assert.False(member.Changed); Assert.Single(fixture.Writes);
    }

    [Theory]
    [InlineData("absent")] [InlineData("null")] [InlineData("empty")] [InlineData("opaque")]
    public void Entry_uncertain_security_readback_accepts_valid_raw_states_without_normalization(string state)
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        entry.ObjectSecurity.SetOwner(new SecurityIdentifier(U2, 0));
        entry.WriteRequestOverride = request => { fixture.Writes.Add(request); throw new TimeoutException(); };
        Assert.Throws<TimeoutException>(entry.CommitChanges);
        var acl = state == "empty" ? Acl(4)
            : state == "opaque" ? AclWithTail(4, new byte[] { 9, 8, 7, 6 }, new byte[] { 0x42, 0, 4, 0 }) : null;
        fixture.Raw = Build(U1, U1, acl, nullDacl: state == "null", gapBefore: 4, tail: new byte[] { 3, 2, 1, 0 });
        var expected = (byte[])fixture.Raw.Clone();
        entry.Options.SecurityMasks = AdForLinux.DirectoryServices.SecurityMasks.Owner;
        entry.PropertyReadOverride = (_, _) =>
        {
            var result = new PropertyCollection();
            result.ReplaceLoaded("nTSecurityDescriptor", new object[] { fixture.Raw });
            return result;
        };
        entry.RefreshCache(new[] { "nTSecurityDescriptor" }); entry.CommitChanges();
        Assert.Single(fixture.Writes);
        Assert.Equal(expected, Assert.IsType<byte[]>(entry.Properties["nTSecurityDescriptor"].Value));
        Assert.Equal(expected, entry.ObjectSecurity._securityDescriptor.MutationState.Descriptor.GetBinaryForm());
        Assert.Equal(AdForLinux.DirectoryServices.SecurityMasks.None, entry.ObjectSecurity.PendingWriteSections);
    }
}
