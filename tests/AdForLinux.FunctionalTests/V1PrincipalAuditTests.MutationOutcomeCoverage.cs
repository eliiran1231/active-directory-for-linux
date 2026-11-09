using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Principal_delete_publishes_deleted_state_only_after_server_acknowledgement(bool reject)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var searcher = fixture.Search(query);
        using var principal = searcher.FindOne()!;
        var entry = Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject());
        fixture.MutationResult = reject ? ResultCode.InsufficientAccessRights : ResultCode.Success;

        if (reject)
        {
            Assert.Throws<UnauthorizedAccessException>(() => principal.Delete());
            Assert.False(principal.IsDeleted);
            Assert.False(entry.IsDisposed);
            Assert.Same(entry, principal.GetUnderlyingObject());
            Assert.Equal("found-account", principal.SamAccountName);
            fixture.MutationResult = ResultCode.Success;
            principal.Delete();
        }
        else principal.Delete();

        Assert.True(principal.IsDeleted);
        Assert.True(entry.IsDisposed);
        Assert.All(fixture.Writes, request => Assert.Equal("CN=found,DC=example,DC=test", Assert.IsType<DeleteRequest>(request).DistinguishedName));
        Assert.Equal(reject ? 2 : 1, fixture.Writes.Count);
        var sends = fixture.Writes.Count;
        Assert.Throws<InvalidOperationException>(() => principal.Delete());
        Assert.Throws<InvalidOperationException>(() => principal.Save());
        Assert.Throws<InvalidOperationException>(() => _ = principal.SamAccountName);
        Assert.Equal(sends, fixture.Writes.Count);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Rename_and_move_publish_new_path_only_after_acknowledgement(bool move, bool reject)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var searcher = fixture.Search(query);
        using var principal = searcher.FindOne()!;
        var entry = Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject());
        using var destination = entry.CreateEntryForDn("OU=destination,DC=example,DC=test");
        var before = entry.Path;
        var parent = move ? "OU=destination,DC=example,DC=test" : "DC=example,DC=test";
        fixture.MutationResult = reject ? ResultCode.UnwillingToPerform : ResultCode.Success;
        void Mutate() { if (move) entry.MoveTo(destination, "CN=renamed"); else entry.Rename("CN=renamed"); }

        if (reject)
        {
            Assert.Throws<DirectoryServicesCOMException>(Mutate);
            Assert.Equal(before, entry.Path);
            Assert.Equal("found description", entry.Properties["description"].Value);
            fixture.MutationResult = ResultCode.Success;
            Mutate();
        }
        else Mutate();

        Assert.Equal(before.Replace("CN=found,DC=example,DC=test", "CN=renamed," + parent, StringComparison.Ordinal), entry.Path);
        Assert.False(entry.IsDisposed);
        Assert.Equal(reject ? 2 : 1, fixture.Writes.Count);
        Assert.All(fixture.Writes, request =>
        {
            var rename = Assert.IsType<ModifyDNRequest>(request);
            Assert.Equal("CN=found,DC=example,DC=test", rename.DistinguishedName);
            Assert.Equal(parent, rename.NewParentDistinguishedName);
            Assert.Equal("CN=renamed", rename.NewName);
            Assert.True(rename.DeleteOldRdn);
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Lost_rename_or_move_response_does_not_claim_the_destination_path(bool move)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new UserPrincipal(fixture.Context);
        using var searcher = fixture.Search(query);
        using var principal = searcher.FindOne()!;
        var entry = Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject());
        using var destination = entry.CreateEntryForDn("OU=destination,DC=example,DC=test");
        var original = entry.Path;
        fixture.LoseMutationResponse = true;
        Assert.Throws<TimeoutException>(() =>
        {
            if (move) entry.MoveTo(destination, "CN=renamed");
            else entry.Rename("CN=renamed");
        });
        Assert.Equal(original, entry.Path);
        Assert.False(entry.IsDisposed);
        Assert.IsType<ModifyDNRequest>(Assert.Single(fixture.Writes));
        // Path retention reports only local state: the server outcome is unknown.
    }
}
