#pragma warning disable CA1416
using System.Security.AccessControl;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Theory]
    [InlineData("owner", false)] [InlineData("group", false)] [InlineData("access", false)] [InlineData("audit", false)]
    [InlineData("owner", true)] [InlineData("group", true)] [InlineData("access", true)] [InlineData("audit", true)]
    public void Public_entry_identity_reads_use_automatic_context_without_attaching_authority_to_copies(string route, bool ambient)
    {
        using var fixture = new IdentityFixture(ambient);
        var bytes = Build(U1, U1, Acl(4, Ace(0, 0, 16, U1)), Acl(4, Ace(2, 64, 16, U1)));
        fixture.Entry.Options.SecurityMasks = AllEntrySections;
        fixture.Entry.SecurityReadOverride = _ => (byte[])bytes.Clone();
        var source = fixture.Entry.ObjectSecurity;
        var before = source.CaptureInteropSnapshot();
        var name = route switch
        {
            "owner" => source.GetOwner(typeof(NTAccount))!,
            "group" => source.GetGroup(typeof(NTAccount))!,
            "access" => Assert.Single(source.GetAccessRules(true, false, typeof(NTAccount)).Cast<ActiveDirectoryAccessRule>()).IdentityReference,
            _ => Assert.Single(source.GetAuditRules(true, false, typeof(NTAccount)).Cast<ActiveDirectoryAuditRule>()).IdentityReference,
        };
        Assert.Equal("EXAMPLE\\alice", name.Value);
        Assert.Equal(1, fixture.Opened); Assert.Equal(fixture.Opened, fixture.Closed);
        Assert.Single(fixture.AccountRequests);
        Assert.Equal(before.Raw, source.CaptureInteropSnapshot().Raw);
        Assert.Equal(before.Generation, source.CaptureInteropSnapshot().Generation);
        Assert.Equal(AdForLinux.DirectoryServices.SecurityMasks.None, source.PendingWriteSections);
        // A byte copy has identity data, not the entry's resolver or credentials.
        var copy = new ActiveDirectorySecurity(); copy.SetSecurityDescriptorBinaryForm(bytes);
        Assert.Throws<NotSupportedException>(() => copy.GetOwner(typeof(NTAccount)));
        fixture.Entry.Close();
        Assert.Throws<InvalidOperationException>(() => source.GetOwner(typeof(NTAccount)));
        Assert.Equal(1, fixture.Opened);
    }

    [Theory]
    [InlineData("owner", false)] [InlineData("group", false)] [InlineData("access", false)] [InlineData("audit", false)]
    [InlineData("owner", true)] [InlineData("group", true)] [InlineData("access", true)] [InlineData("audit", true)]
    public void Public_entry_name_mutation_retains_authority_policy_and_exact_section_intent(string route, bool ambient)
    {
        using var fixture = new IdentityFixture(ambient);
        fixture.Entry.Options.SecurityMasks = AllEntrySections;
        fixture.Entry.SecurityReadOverride = _ => Build(U2, U2, Acl(4), Acl(4));
        var source = fixture.Entry.ObjectSecurity;
        var before = StateBoundary.Take(source);
        void Change()
        {
            var name = new NTAccount("EXAMPLE", "alice");
            switch (route)
            {
                case "owner": source.SetOwner(name); break;
                case "group": source.SetGroup(name); break;
                case "access": source.AddAccessRule(new ActiveDirectoryAccessRule(name, ActiveDirectoryRights.ReadProperty, AccessControlType.Allow)); break;
                default: source.AddAuditRule(new ActiveDirectoryAuditRule(name, ActiveDirectoryRights.ReadProperty, AuditFlags.Success)); break;
            }
        }
        if (ambient)
        {
            Assert.Throws<NotSupportedException>(Change);
            AssertBoundRollback(before);
            Assert.Equal(0, fixture.Opened); Assert.Empty(fixture.Requests);
        }
        else
        {
            Change();
            var expected = route switch { "owner" => AdForLinux.DirectoryServices.SecurityMasks.Owner,
                "group" => AdForLinux.DirectoryServices.SecurityMasks.Group, "access" => AdForLinux.DirectoryServices.SecurityMasks.Dacl,
                _ => AdForLinux.DirectoryServices.SecurityMasks.Sacl };
            Assert.Equal(expected, source.PendingWriteSections);
            Assert.True(source.CaptureInteropSnapshot().Generation > before.Snapshot.Generation);
            Assert.Equal(1, fixture.Opened); Assert.Equal(1, fixture.Closed); Assert.Single(fixture.AccountRequests);
        }
        // Fake sessions establish routing/lifetime policy only, not OS Negotiate support.
    }
}
