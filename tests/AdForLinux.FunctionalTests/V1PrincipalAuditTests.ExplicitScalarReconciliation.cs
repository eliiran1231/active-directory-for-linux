using System.DirectoryServices.Protocols;
using System.Text;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Explicit_scalar_reconciliation_after_uncertain_save_preserves_the_observed_server_value(bool applied)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.User.Description = "requested";
        fixture.State.Outcome = "lost";
        fixture.State.ApplyBeforeResponseLoss = applied;
        Assert.Throws<TimeoutException>(fixture.User.Save);
        Assert.Equal(1, fixture.State.Submissions);
        Assert.Equal(1, fixture.State.Disposals);

        fixture.Entry.RefreshCache(["description"]);
        var observed = Assert.IsType<string>(fixture.Entry.Properties["description"].Value);
        Assert.Equal(applied ? "requested" : "before", observed);
        // Principal setters intentionally retain intent across a raw entry
        // refresh. Explicitly accept the observed value at the principal layer.
        fixture.User.Description = observed;
        fixture.User.DisplayName = "later edit";
        fixture.State.Outcome = "success";
        fixture.User.Save();

        Assert.Equal(2, fixture.State.Invocations);
        Assert.Equal(2, fixture.State.Submissions);
        Assert.Equal(2, fixture.State.Disposals);
        Assert.Equal(observed, Assert.Single(fixture.State.Server["description"]));
        Assert.Equal("later edit", Assert.Single(fixture.State.Server["displayName"]));
        var final = fixture.State.Commands[1];
        Assert.Equal(2, final.Changes.Length);
        var description = Assert.Single(final.Changes, change => change.Name == "description");
        Assert.Equal(DirectoryAttributeOperation.Replace, description.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(applied ? "requested" : "before"), Assert.Single(description.Values));
        var displayName = Assert.Single(final.Changes, change => change.Name == "displayName");
        Assert.Equal(DirectoryAttributeOperation.Replace, displayName.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes("later edit"), Assert.Single(displayName.Values));
        Assert.Single(fixture.State.Commands.SelectMany(command => command.Changes), change => change.Name == "displayName");
    }
}
