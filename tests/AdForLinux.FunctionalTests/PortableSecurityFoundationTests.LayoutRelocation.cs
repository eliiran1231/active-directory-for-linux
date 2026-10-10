#pragma warning disable CA1416
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Tests.Shared;
using AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> ReferencedSuffixCases() => LayoutRelocationCases.Matrix();

    [Theory]
    [MemberData(nameof(ReferencedSuffixCases))]
    public void Entry_relocates_only_referenced_suffix_with_shared_state_and_exact_section_write(string section, bool grow, int gap, int fill)
    {
        using var fixture = new EntryWriteFixture();
        var original = LayoutRelocationCases.Image(section, grow, gap, fill, false);
        fixture.Raw = (byte[])original.Clone();
        var source = fixture.Entry.ObjectSecurity;
        var peer = new ActiveDirectorySecurity(source._securityDescriptor, AllEntrySections);
        var alias = IdenticalAlias(source._securityDescriptor);
        var aliasBefore = StateBoundary.Take(alias);
        var before = source.CaptureInteropSnapshot();
        LayoutRelocationCases.Edit(peer, section, grow);
        var after = source.CaptureInteropSnapshot();
        Assert.Equal(LayoutRelocationCases.Image(section, grow, gap, fill, true), after.Raw);
        Assert.Equal(original, after.Original);
        Assert.Equal(original, fixture.Raw);
        Assert.Equal(original.AsSpan(20, gap).ToArray(), after.Raw.AsSpan(20, gap).ToArray());
        Assert.True(after.Generation > before.Generation);
        Assert.Equal(LayoutRelocationCases.Mask(section), after.Pending);
        Assert.Equal(peer.GetSecurityDescriptorBinaryForm(), source.GetSecurityDescriptorBinaryForm());
        Assert.Equal(before.Source, after.Source);
        Assert.Equal(before.Attachment, after.Attachment);
        // ACL aliases observe the shared ACL mutation while retaining their own
        // original provenance; identity-only edits do not propagate to this wrapper.
        var permitted = section == "dacl" ? AccessControlSections.Access
            : section == "sacl" ? AccessControlSections.Audit : AccessControlSections.None;
        aliasBefore.Check(permitted, true, false);
        if (permitted != AccessControlSections.None)
        {
            var field = section == "dacl" ? 16 : 12;
            Assert.Equal(ReplacementComponent(after.Raw, field), ReplacementComponent(alias.CaptureInteropSnapshot().Raw, field));
            Assert.True(alias.CaptureInteropSnapshot().Generation > aliasBefore.Snapshot.Generation);
        }
        LayoutRelocationCases.Edit(peer, section, grow);
        Assert.Equal(after.Raw, source.CaptureInteropSnapshot().Raw);
        Assert.Equal(after.Generation, source.CaptureInteropSnapshot().Generation);
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)), LayoutRelocationCases.Mask(section), after.Raw);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Failed_interior_relocation_restores_bound_shared_state_and_allows_safe_edit(bool trailer)
    {
        using var fixture = new EntryWriteFixture();
        fixture.Raw = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4),
            gapBefore: trailer ? 0 : 4, tail: trailer ? new byte[] { 0, 0, 0, 0 } : null);
        var source = fixture.Entry.ObjectSecurity;
        var peer = new ActiveDirectorySecurity(source._securityDescriptor, AllEntrySections);
        var alias = IdenticalAlias(source._securityDescriptor);
        source.SetGroup(new SecurityIdentifier(U2, 0));
        var before = StateBoundary.Take(source);
        var other = new[] { StateBoundary.Take(peer), StateBoundary.Take(alias) };
        Assert.Throws<InvalidOperationException>(() => peer.SetOwner(new SecurityIdentifier(Everyone, 0)));
        AssertBoundRollback(before);
        foreach (var state in other) state.Check(AccessControlSections.None, false, false);
        Assert.Empty(fixture.Writes);
        source.SetOwner(new SecurityIdentifier(U2, 0));
        fixture.Entry.CommitChanges();
        AssertIdenticalWrite(Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes)),
            AdForLinux.DirectoryServices.SecurityMasks.Owner | AdForLinux.DirectoryServices.SecurityMasks.Group,
            source.CaptureInteropSnapshot().Raw);
    }

}
