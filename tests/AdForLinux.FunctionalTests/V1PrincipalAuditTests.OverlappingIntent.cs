using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Equivalent_scalar_and_extension_edits_share_one_modification_and_acknowledge_both(bool extensionFirst, bool rejectFirst)
    {
        using var fixture = new Fixture();
        fixture.Server["description"] = ["before"];
        using var user = fixture.Attach(new MaterializedCustomUser(fixture.Context));
        if (extensionFirst) user.WriteAttribute("description", "requested");
        user.Description = "requested";
        if (!extensionFirst) user.WriteAttribute("description", "requested");
        if (rejectFirst)
        {
            fixture.Fail = true;
            Assert.Throws<InvalidOperationException>(user.Save);
            Assert.Empty(fixture.Writes);
            Assert.Equal("before", Assert.Single(fixture.Server["description"]));
            fixture.Fail = false;
        }

        user.Save();
        Assert.Equal(rejectFirst ? 2 : 1, fixture.Attempts);
        var change = Assert.Single(Assert.Single(fixture.Writes).Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal("requested", Assert.Single(change.Cast<object>()));
        Assert.Equal("requested", Assert.Single(user.ReadAttribute("description")));
        fixture.Server["description"] = ["external"];
        user.DisplayName = "later edit";
        user.Save();
        Assert.Equal(2, fixture.Writes.Count);
        Assert.Equal("displayName", Assert.Single(fixture.Writes[1].Modifications.Cast<DirectoryAttributeModification>()).Name);
        Assert.Equal("external", Assert.Single(fixture.Server["description"]));
    }

    [Theory]
    [InlineData("description")]
    [InlineData("department")]
    public void Partial_readback_of_mixed_principal_edits_cannot_release_entry_write_quarantine(string firstAttribute)
    {
        using var fixture = new Fixture();
        fixture.Server["description"] = ["old description"];
        fixture.Server["department"] = ["old department"];
        using var user = fixture.Attach(new MaterializedCustomUser(fixture.Context));
        user.Description = "sent description";
        user.WriteAttribute("department", "sent department");
        fixture.AfterWrite = () => throw new TimeoutException("controlled mixed response loss");
        Assert.Throws<TimeoutException>(user.Save);
        Assert.Equal(1, fixture.Attempts);
        Assert.Single(fixture.Writes);
        fixture.AfterWrite = null;

        var before = fixture.Reads.Count;
        fixture.Entry.RefreshCache([firstAttribute]);
        Assert.Equal(before + 1, fixture.Reads.Count);
        Assert.Equal(new[] { firstAttribute }, fixture.Reads[^1]);
        Assert.Equal("sent " + firstAttribute, fixture.Entry.Properties[firstAttribute].Value);
        Assert.Throws<InvalidOperationException>(fixture.Entry.CommitChanges);
        Assert.Equal(1, fixture.Attempts);

        fixture.Entry.RefreshCache(["description", "department"]);
        Assert.Equal(before + 2, fixture.Reads.Count);
        fixture.Entry.CommitChanges();
        Assert.Equal(1, fixture.Attempts);
        Assert.Single(fixture.Writes);
        Assert.Equal("sent description", fixture.Entry.Properties["description"].Value);
        Assert.Equal("sent department", fixture.Entry.Properties["department"].Value);
    }
}
