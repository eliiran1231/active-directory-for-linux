#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using EntryMasks = AdForLinux.DirectoryServices.SecurityMasks;
using WireMasks = System.DirectoryServices.Protocols.SecurityMasks;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData(AccessControlSections.Owner, EntryMasks.Owner)]
    [InlineData(AccessControlSections.Group, EntryMasks.Group)]
    [InlineData(AccessControlSections.Access, EntryMasks.Dacl)]
    [InlineData(AccessControlSections.Audit, EntryMasks.Sacl)]
    [InlineData(AccessControlSections.All, EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl | EntryMasks.Sacl)]
    public void Raw_write_section_enum_mapping_is_explicit(AccessControlSections input, EntryMasks expected)
        => Assert.Equal(expected, A.RawSecurityWritePreparation.Masks(input));

    [Fact]
    public void Raw_modify_preparation_preserves_unknown_bytes_and_omits_read_only_normalization()
    {
        using var fixture = new IdentityFixture();
        var raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1), Ace(0, 0, 32, U1)),
            AclWithTail(4, new byte[] { 1, 2, 3, 4 }, Ace(2, 0x40, 16, U1)));
        var descriptor = new A.CommonSecurityDescriptor(true, true, raw, 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        wrapper.SetRawReadContext(EntryMasks.Owner | EntryMasks.Group | EntryMasks.Dacl, fixture.Resolver);
        fixture.Resolver.Bind(wrapper);
        Assert.NotEqual(raw, wrapper.GetSecurityDescriptorBinaryForm());
        var clean = A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.None);
        var noOp = new ModifyRequest("DC=example,DC=com");
        A.RawSecurityWritePreparation.AppendModify(wrapper, clean, noOp);
        Assert.Empty(noOp.Modifications.Cast<DirectoryAttributeModification>()); Assert.Empty(noOp.Controls.Cast<DirectoryControl>());

        wrapper.SetOwner(new SecurityIdentifier(U2, 0));
        var plan = A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.Owner);
        var request = new ModifyRequest("DC=example,DC=com");
        A.RawSecurityWritePreparation.AppendModify(wrapper, plan, request);
        var modification = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal(DirectoryAttributeOperation.Replace, modification.Operation);
        Assert.Equal("nTSecurityDescriptor", modification.Name);
        Assert.Equal(descriptor.MutationState.Descriptor.GetBinaryForm(), Assert.IsType<byte[]>(modification[0]));
        Assert.Equal(WireMasks.Owner, Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
        Assert.Equal(new uint[] { 16, 32 }, descriptor.MutationState.Descriptor.Dacl!.Aces.Select(a => a.AccessMask));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, descriptor.MutationState.Descriptor.Sacl!.Trailing.ToArray());
        var exported = plan.GetBinaryForm(); Array.Clear(exported);
        Assert.NotEqual(exported, plan.GetBinaryForm());
        Assert.Equal(0, fixture.Opened); // preparation and numeric changes never bind
    }

    [Theory]
    [InlineData("version")]
    [InlineData("rebind")]
    [InlineData("wrapper")]
    [InlineData("read-context")]
    [InlineData("duplicate")]
    [InlineData("target")]
    public void Prepared_raw_requests_reject_stale_context_or_wrong_destination(string kind)
    {
        using var fixture = new IdentityFixture();
        var descriptor = new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0);
        var wrapper = new FacadeContracts.Wrapper(descriptor); wrapper.SetRawReadContext(EntryMasks.Owner | EntryMasks.Dacl, fixture.Resolver);
        fixture.Resolver.Bind(wrapper);
        wrapper.SetOwner(new SecurityIdentifier(U2, 0));
        var plan = A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.Owner);
        var request = new ModifyRequest("DC=example,DC=com");
        switch (kind)
        {
            case "version": descriptor.Group = new SecurityIdentifier(U2, 0); break;
            case "rebind": fixture.Entry.Password = "changed"; break;
            case "wrapper": wrapper = new FacadeContracts.Wrapper(descriptor); fixture.Resolver.Bind(wrapper); break;
            case "read-context": fixture.Resolver.Bind(wrapper); break;
            case "target": request.DistinguishedName = "CN=other,DC=example,DC=com"; break;
            case "duplicate": request.Controls.Add(new SecurityDescriptorFlagControl(WireMasks.Owner)); break;
        }
        Assert.Throws<InvalidOperationException>(() => A.RawSecurityWritePreparation.AppendModify(wrapper, plan, request));
        Assert.Empty(request.Modifications.Cast<DirectoryAttributeModification>());
    }

    [Fact]
    public void Raw_preparation_refuses_unread_sections_and_detached_creation_defaults()
    {
        using var fixture = new IdentityFixture();
        var wrapper = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0));
        fixture.Resolver.Bind(wrapper);
        Assert.Throws<InvalidOperationException>(() => A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.None));
        wrapper.SetRawReadContext(EntryMasks.Owner, fixture.Resolver);
        Assert.Throws<InvalidOperationException>(() => wrapper.SetGroup(new SecurityIdentifier(U2, 0)));
        wrapper.Descriptor.Group = new SecurityIdentifier(U2, 0); // shared facade edits are caught again at preparation
        Assert.Throws<InvalidOperationException>(() => A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.Group));
        Assert.Null(A.RawSecurityWritePreparation.PrepareAdd(null, EntryMasks.None));
        Assert.Throws<NotSupportedException>(() => A.RawSecurityWritePreparation.PrepareAdd(wrapper.GetSecurityDescriptorBinaryForm(), EntryMasks.Owner));
        Assert.Throws<ArgumentOutOfRangeException>(() => A.RawSecurityWritePreparation.Masks((AccessControlSections)16));
        Assert.Equal(0, fixture.Opened);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Controlled_entry_refresh_invalidates_only_successful_descriptor_refresh(bool includesDescriptor, bool fail)
    {
        using var fixture = new IdentityFixture(); var resolver = fixture.Resolver;
        fixture.Entry.PropertyReadOverride = (properties, all) =>
        {
            if (fail) throw new TimeoutException("controlled refresh failure");
            return new PropertyCollection();
        };
        Action refresh = () => fixture.Entry.RefreshCache(includesDescriptor ? new[] { "nTSecurityDescriptor" } : new[] { "description" });
        if (fail) Assert.Throws<TimeoutException>(refresh); else refresh();
        if (includesDescriptor && !fail)
            Assert.Throws<InvalidOperationException>(() => resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)));
        else Assert.Equal("EXAMPLE\\alice", resolver.Translate(new SecurityIdentifier(U1, 0), typeof(NTAccount)).Value);
    }

    [Fact]
    public void Full_controlled_refresh_expires_retained_wrapper_without_discarding_its_sid_data()
    {
        using var fixture = new IdentityFixture();
        var wrapper = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0));
        fixture.Resolver.Bind(wrapper);
        fixture.Entry.PropertyReadOverride = (_, _) => new PropertyCollection();
        fixture.Entry.RefreshCache();
        Assert.Throws<InvalidOperationException>(() => wrapper.GetOwner(typeof(NTAccount)));
        Assert.Equal(new SecurityIdentifier(U1, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        fixture.Resolver.Bind(wrapper);
        Assert.Equal("EXAMPLE\\alice", wrapper.GetOwner(typeof(NTAccount))!.Value);
    }

    [Fact]
    public void Explicit_resolver_rebinding_never_promotes_a_source_read_baseline_to_destination_authority()
    {
        using var source = new IdentityFixture(); using var destination = new IdentityFixture();
        var wrapper = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, Build(U1, U1, Acl(4), null), 0));
        wrapper.SetRawReadContext(EntryMasks.Owner, source.Resolver);
        source.Resolver.Bind(wrapper); wrapper.SetOwner(new SecurityIdentifier(U2, 0));
        destination.Resolver.Bind(wrapper);
        Assert.Throws<InvalidOperationException>(() => A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.Owner));
        Assert.Equal(new SecurityIdentifier(U2, 0), wrapper.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(0, source.Opened); Assert.Equal(0, destination.Opened);
    }

    [Fact]
    public void Reverted_raw_edit_remains_a_no_op_even_with_native_dirty_flags()
    {
        using var fixture = new IdentityFixture();
        var raw = Build(U1, U1, Acl(4), null);
        var wrapper = new FacadeContracts.Wrapper(new A.CommonSecurityDescriptor(true, true, raw, 0));
        wrapper.SetRawReadContext(EntryMasks.Owner, fixture.Resolver); fixture.Resolver.Bind(wrapper);
        wrapper.SetOwner(new SecurityIdentifier(U2, 0)); wrapper.SetOwner(new SecurityIdentifier(U1, 0));
        Assert.True(wrapper.Flags()[0]);
        var plan = A.RawSecurityWritePreparation.PrepareModify(wrapper, EntryMasks.Owner);
        Assert.Equal(EntryMasks.None, plan.Sections); Assert.Equal(raw, plan.GetBinaryForm());
        var request = new ModifyRequest("DC=example,DC=com");
        A.RawSecurityWritePreparation.AppendModify(wrapper, plan, request);
        Assert.Empty(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.True(wrapper.Flags()[0]); // preparation never clears pending caller state
    }
}
