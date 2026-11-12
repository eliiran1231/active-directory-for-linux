using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    [Theory]
    [InlineData("not-sent")]
    [InlineData("rejected")]
    [InlineData("lost")]
    public void Failed_public_cache_mode_flush_retains_cached_mode_and_recovers_without_replaying_uncertain_write(string outcome)
    {
        using var fixture = new NeutralCreationFixture();
        // Establish a persisted entry through the public Add path, then use the
        // actual neutral property reader and Modify dispatcher for this test.
        fixture.Child.CommitChanges();
        Assert.IsType<LdapAddCommand>(Assert.Single(fixture.Submissions));
        fixture.AssertReleased(1);
        var description = fixture.Child.Properties["description"];
        Assert.Equal("created café", description.Value);
        fixture.AssertReleased(2);
        Assert.Equal(2, fixture.Reads.Count);
        description.Value = "pending mode-switch edit";
        fixture.Outcome = outcome;
        fixture.ApplyLostAdd = true; // despite the fixture name, applies the submitted Modify as well

        var failure = Record.Exception(() => fixture.Child.UsePropertyCache = false);
        if (outcome == "not-sent") Assert.Same(fixture.NotSent, failure);
        else if (outcome == "lost") Assert.Same(fixture.LostResponse, failure);
        else Assert.Equal((int)ResultCode.InsufficientAccessRights,
            Assert.IsType<DirectoryServicesCOMException>(failure).ExtendedError);
        Assert.True(fixture.Child.UsePropertyCache);
        Assert.True(description.Changed);
        Assert.Same(description, fixture.Child.Properties["description"]);
        Assert.Equal("pending mode-switch edit", description.Value);
        fixture.AssertReleased(3);
        Assert.Equal(2, fixture.Invocations.Count);
        Assert.Equal(outcome == "not-sent" ? 1 : 2, fixture.Submissions.Count);
        Assert.Equal(2, fixture.Reads.Count);
        Assert.Equal(outcome == "lost" ? "pending mode-switch edit" : "created café",
            Assert.Single(fixture.Server["description"]));

        fixture.Outcome = "success";
        if (outcome == "lost")
        {
            // The failed setter must not turn the same assignment into a no-op
            // or bypass the uncertain-write gate. No newer edit is introduced:
            // readback can reconcile the exact submitted ledger, by design.
            Assert.Throws<InvalidOperationException>(() => fixture.Child.UsePropertyCache = false);
            Assert.Throws<InvalidOperationException>(fixture.Child.CommitChanges);
            Assert.True(fixture.Child.UsePropertyCache);
            fixture.AssertReleased(3);
            Assert.Equal(2, fixture.Invocations.Count);
            Assert.Equal(2, fixture.Submissions.Count);
            fixture.Child.RefreshCache(["description"]);
            Assert.Equal("pending mode-switch edit", fixture.Child.Properties["description"].Value);
            Assert.False(description.Changed);
            fixture.AssertReleased(4);
            Assert.Equal(4, fixture.Reads.Count);
        }

        fixture.Child.UsePropertyCache = false;
        Assert.False(fixture.Child.UsePropertyCache);
        Assert.False(description.Changed);
        fixture.AssertReleased(4);
        var beforeImmediate = fixture.Submissions.Count;
        Assert.Equal(outcome == "rejected" ? 3 : 2, beforeImmediate);
        Assert.Equal("pending mode-switch edit", Assert.Single(fixture.Server["description"]));

        // Repeating an acknowledged mode setting sends nothing. The following
        // edit must now dispatch immediately, proving the final mode behavior.
        fixture.Child.UsePropertyCache = false;
        fixture.AssertReleased(4);
        fixture.Child.Properties["description"].Value = "immediate follow-up";
        var immediate = Assert.IsType<LdapModifyCommand>(fixture.Submissions.Last());
        Assert.Equal(NeutralCreationFixture.Dn, immediate.DistinguishedName);
        Assert.Empty(immediate.Controls);
        var change = Assert.Single(immediate.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes("immediate follow-up"), Assert.Single(change.Values));
        Assert.Equal(beforeImmediate + 1, fixture.Submissions.Count);
        Assert.Equal("immediate follow-up", Assert.Single(fixture.Server["description"]));
        fixture.AssertReleased(6);
        Assert.Equal(outcome == "lost" ? 6 : 4, fixture.Reads.Count);
        Assert.All(fixture.Submissions.Skip(1), command => Assert.IsType<LdapModifyCommand>(command));
        fixture.Child.CommitChanges();
        fixture.AssertReleased(6);
        Assert.Equal(beforeImmediate + 1, fixture.Submissions.Count);
        // Controlled normalized transport data: no native/AD execution,
        // Microsoft runtime parity or concurrent-entry contract is asserted.
    }
}
