using System.DirectoryServices.Protocols;
using System.Text;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [DirectoryObjectClass("group")]
    [DirectoryRdnPrefix("CN")]
    public sealed class PhaseExtensionGroup(PrincipalContext context) : GroupPrincipal(context)
    {
        public void WriteExtension(object? value) => ExtensionSet("extensionAttribute1", value);
        public object?[] ReadExtension() => ExtensionGet("extensionAttribute1");
    }

    private static void AssertGroupScalarAndExtensionCommand(LdapModifyCommand command,
        string scalar, string[]? extension)
    {
        Assert.Equal(MembershipFixture.GroupDn, command.DistinguishedName);
        Assert.Empty(command.Controls);
        Assert.Equal(2, command.Changes.Length);
        var description = Assert.Single(command.Changes, change => change.Name == "description");
        Assert.Equal(DirectoryAttributeOperation.Replace, description.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(scalar), Assert.Single(description.Values));
        var custom = Assert.Single(command.Changes, change => change.Name == "extensionAttribute1");
        if (extension is null)
            Assert.True(custom.Operation is DirectoryAttributeOperation.Delete or DirectoryAttributeOperation.Replace);
        else Assert.Equal(DirectoryAttributeOperation.Replace, custom.Operation);
        Assert.Equal(extension?.Length ?? 0, custom.Values.Length);
        if (extension is not null)
            for (var index = 0; index < extension.Length; index++)
                Assert.Equal(Encoding.UTF8.GetBytes(extension[index]), custom.Values[index]);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Explicit_group_extension_replacement_or_clear_after_rejection_is_acknowledged_by_successful_save(
        bool rejectMembershipPhase, bool clear)
    {
        using var fixture = new MembershipFixture(typeof(PhaseExtensionGroup));
        var group = Assert.IsType<PhaseExtensionGroup>(fixture.Group);
        fixture.ServerScalars["extensionAttribute1"] = ["before extension"];
        fixture.Stage();
        group.Description = "first scalar";
        group.WriteExtension(new object[] { "first extension" });
        fixture.ScalarOutcome = rejectMembershipPhase ? "success" : "rejected";
        fixture.Outcome = rejectMembershipPhase ? "rejected" : "success";

        Assert.Throws<UnauthorizedAccessException>(group.Save);
        Assert.Equal(rejectMembershipPhase ? 2 : 1, fixture.Invocations.Count);
        Assert.Equal(rejectMembershipPhase ? 2 : 1, fixture.Submissions.Count);
        AssertGroupScalarAndExtensionCommand(fixture.Invocations[0], "first scalar", ["first extension"]);
        if (rejectMembershipPhase) AssertMembershipDelta(fixture.Invocations[1]);
        Assert.Equal(rejectMembershipPhase ? "first scalar" : "before", Assert.Single(fixture.ServerScalars["description"]));
        Assert.Equal(rejectMembershipPhase ? "first extension" : "before extension",
            Assert.Single(fixture.ServerScalars["extensionAttribute1"]));
        // Cached extension values are local intent, not evidence of server state.
        Assert.Equal(new object?[] { "first extension" }, group.ReadExtension());
        Assert.True(group.HasReferentialPropertiesSet);
        Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(0, fixture.Acknowledgements);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(rejectMembershipPhase ? 3 : 2);

        // Explicitly replace the old intent after a definitive rejection. No
        // assertion here requires early extension acknowledgement or prescribes
        // an unmodified retry after partial/unknown multi-step Save outcomes.
        group.Description = "reconciled scalar";
        group.WriteExtension(clear ? null : new object[] { "new extension", "second value" });
        Assert.True(group.Members.Remove(fixture.Added));
        group.Members.Add(fixture.Removed);
        Assert.False(group.HasReferentialPropertiesSet);
        fixture.ScalarOutcome = "success";
        fixture.Outcome = "success";
        group.Save();
        var successfulIndex = rejectMembershipPhase ? 2 : 1;
        Assert.Equal(successfulIndex + 1, fixture.Invocations.Count);
        AssertGroupScalarAndExtensionCommand(fixture.Invocations[successfulIndex], "reconciled scalar",
            clear ? null : ["new extension", "second value"]);
        Assert.Equal("reconciled scalar", Assert.Single(fixture.ServerScalars["description"]));
        if (clear) Assert.False(fixture.ServerScalars.ContainsKey("extensionAttribute1"));
        else Assert.Equal(new object[] { "new extension", "second value" }, fixture.ServerScalars["extensionAttribute1"]);
        Assert.Equal(0, fixture.Acknowledgements); // cancelled membership never submitted successfully
        fixture.AssertReleased(rejectMembershipPhase ? 4 : 3);

        // After full success, an unrelated public scalar save must not repeat
        // either the acknowledged extension change or cancelled membership.
        fixture.ServerScalars["extensionAttribute1"] = ["external fixture value"];
        group.Description = "unrelated scalar";
        group.Save();
        Assert.Equal(successfulIndex + 2, fixture.Invocations.Count);
        Assert.Equal(successfulIndex + 2, fixture.Submissions.Count);
        AssertGroupDescriptionCommand(fixture.Invocations[^1], "unrelated scalar");
        Assert.Equal("external fixture value", Assert.Single(fixture.ServerScalars["extensionAttribute1"]));
        Assert.Equal(new[] { MembershipFixture.KeptDn, MembershipFixture.RemovedDn },
            fixture.ServerMembers.OrderBy(value => value, StringComparer.Ordinal));
        Assert.False(group.HasReferentialPropertiesSet);
        Assert.Equal(0, fixture.PostAckReads);
        fixture.AssertReleased(rejectMembershipPhase ? 5 : 4);
        group.Save();
        Assert.Equal(successfulIndex + 2, fixture.Submissions.Count);
        fixture.AssertReleased(rejectMembershipPhase ? 5 : 4);
    }
}
