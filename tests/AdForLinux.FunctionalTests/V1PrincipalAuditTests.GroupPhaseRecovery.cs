using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private static void AssertGroupDescriptionCommand(LdapModifyCommand command, string value)
    {
        Assert.Equal(MembershipFixture.GroupDn, command.DistinguishedName);
        Assert.Empty(command.Controls);
        var change = Assert.Single(command.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(value), Assert.Single(change.Values));
    }

    [Theory]
    [InlineData("not-sent")]
    [InlineData("rejected")]
    public void Group_scalar_failure_preserves_membership_for_retry_after_a_corrected_scalar_edit(string outcome)
    {
        using var fixture = new MembershipFixture();
        fixture.Stage();
        fixture.Group.Description = "first attempt";
        fixture.ScalarOutcome = outcome;

        var error = Record.Exception(fixture.Group.Save);
        if (outcome == "not-sent") Assert.Same(fixture.BeforeSend, error);
        else Assert.IsType<UnauthorizedAccessException>(error);
        AssertGroupDescriptionCommand(Assert.Single(fixture.Invocations), "first attempt");
        Assert.Equal(outcome == "not-sent" ? 0 : 1, fixture.Submissions.Count);
        Assert.True(fixture.Group.HasReferentialPropertiesSet);
        Assert.Equal("first attempt", fixture.Group.Description);
        Assert.Equal("before", Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(0, fixture.Acknowledgements);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(2); // staging read plus refused scalar operation

        fixture.Group.Description = "corrected edit";
        fixture.ScalarOutcome = "success";
        fixture.Group.Save();

        Assert.Equal(3, fixture.Invocations.Count);
        AssertGroupDescriptionCommand(fixture.Invocations[1], "corrected edit");
        AssertMembershipDelta(fixture.Invocations[2]);
        Assert.Equal(outcome == "not-sent" ? 2 : 3, fixture.Submissions.Count);
        Assert.False(fixture.Group.HasReferentialPropertiesSet);
        Assert.Equal("corrected edit", Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(new[] { MembershipFixture.AddedDn, MembershipFixture.KeptDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(1, fixture.Acknowledgements);
        Assert.Equal(1, fixture.PostAckReads);
        fixture.AssertReleased(4);
        fixture.Group.Save();
        Assert.Equal(3, fixture.Invocations.Count);
        fixture.AssertReleased(4);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Group_uncertain_scalar_phase_defers_membership_until_explicit_readback_reconciliation(bool applied)
    {
        using var fixture = new MembershipFixture();
        fixture.Stage();
        fixture.Group.Description = "uncertain request";
        fixture.ScalarOutcome = "lost";
        fixture.ApplyLost = applied;

        Assert.Same(fixture.Lost, Assert.Throws<TimeoutException>(fixture.Group.Save));
        AssertGroupDescriptionCommand(Assert.Single(fixture.Invocations), "uncertain request");
        Assert.Single(fixture.Submissions);
        Assert.True(fixture.Group.HasReferentialPropertiesSet);
        Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(0, fixture.Acknowledgements);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(2);

        // Read back before retrying Save, then explicitly reconcile principal
        // intent. This avoids both blind replay and the known refused-retry
        // version bug. No membership operation has been submitted yet.
        fixture.GroupEntry.RefreshCache(["description"]);
        var observed = Assert.IsType<string>(fixture.GroupEntry.Properties["description"].Value);
        Assert.Equal(applied ? "uncertain request" : "before", observed);
        Assert.Equal("uncertain request", fixture.Group.Description); // raw refresh retains principal intent
        fixture.Group.Description = observed;
        fixture.ScalarOutcome = "success";
        fixture.Group.Save();

        Assert.Equal(3, fixture.Invocations.Count);
        Assert.Equal(3, fixture.Submissions.Count);
        AssertGroupDescriptionCommand(fixture.Invocations[1], observed);
        AssertMembershipDelta(fixture.Invocations[2]);
        Assert.Equal(observed, Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(new[] { MembershipFixture.AddedDn, MembershipFixture.KeptDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.False(fixture.Group.HasReferentialPropertiesSet);
        Assert.Equal(1, fixture.Acknowledgements);
        Assert.Equal(1, fixture.PostAckReads);
        fixture.AssertReleased(4);
        fixture.Group.Save();
        Assert.Equal(3, fixture.Submissions.Count);
        fixture.AssertReleased(4);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Group_membership_rejection_allows_cancelling_collection_edits_without_replaying_acknowledged_scalar(bool cancelRemovalToo)
    {
        using var fixture = new MembershipFixture();
        fixture.Stage();
        fixture.Group.Description = "acknowledged scalar";
        fixture.Outcome = "rejected";

        Assert.Throws<UnauthorizedAccessException>(fixture.Group.Save);
        Assert.Equal(2, fixture.Invocations.Count);
        AssertGroupDescriptionCommand(fixture.Invocations[0], "acknowledged scalar");
        AssertMembershipDelta(fixture.Invocations[1]);
        Assert.Equal(2, fixture.Submissions.Count);
        Assert.True(fixture.Group.HasReferentialPropertiesSet);
        Assert.Equal("acknowledged scalar", Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(0, fixture.Acknowledgements);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(3);

        // These are sequential public collection edits after a definitive
        // rejection. Unknown-delivery cancellation/retry is a separate contract.
        Assert.True(fixture.Group.Members.Remove(fixture.Added));
        if (cancelRemovalToo) fixture.Group.Members.Add(fixture.Removed);
        Assert.False(fixture.Group.Members.Contains(fixture.Added));
        Assert.Equal(cancelRemovalToo, fixture.Group.Members.Contains(fixture.Removed));
        Assert.Equal(!cancelRemovalToo, fixture.Group.HasReferentialPropertiesSet);
        // Synthetic outside change is a fixture fact. Fixed command assertions
        // below establish non-replay; this is not an AD replication test.
        fixture.ServerScalars["description"] = ["external value"];
        fixture.Outcome = "success";
        fixture.Group.Save();

        if (cancelRemovalToo)
        {
            Assert.Equal(2, fixture.Invocations.Count);
            Assert.Equal(0, fixture.Acknowledgements);
            Assert.Equal(0, fixture.PostAckReads);
        }
        else
        {
            Assert.Equal(3, fixture.Invocations.Count);
            var remaining = fixture.Invocations[2];
            Assert.Equal(MembershipFixture.GroupDn, remaining.DistinguishedName);
            Assert.Empty(remaining.Controls);
            var change = Assert.Single(remaining.Changes);
            Assert.Equal("member", change.Name);
            Assert.Equal(DirectoryAttributeOperation.Delete, change.Operation);
            Assert.Equal(Encoding.UTF8.GetBytes(MembershipFixture.RemovedDn), Assert.Single(change.Values));
            Assert.Equal(1, fixture.Acknowledgements);
            Assert.Equal(1, fixture.PostAckReads);
        }
        Assert.Equal(cancelRemovalToo ? 2 : 3, fixture.Submissions.Count);
        Assert.Equal("external value", Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(cancelRemovalToo
            ? new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn }
            : new[] { MembershipFixture.KeptDn }, fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.False(fixture.Group.HasReferentialPropertiesSet);
        fixture.AssertReleased(cancelRemovalToo ? 3 : 4);
        fixture.Group.Save();
        Assert.Equal(cancelRemovalToo ? 2 : 3, fixture.Submissions.Count);
        fixture.AssertReleased(cancelRemovalToo ? 3 : 4);
    }
}
