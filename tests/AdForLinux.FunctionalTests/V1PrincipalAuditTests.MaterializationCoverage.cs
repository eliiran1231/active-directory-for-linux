using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData("user", typeof(UserPrincipal))]
    [InlineData("group", typeof(GroupPrincipal))]
    [InlineData("computer", typeof(ComputerPrincipal))]
    public void Materialized_principal_retains_identity_values_and_entry_ownership(string leafClass, Type expectedType)
    {
        using var fixture = new Fixture();
        var identity = new Guid("cdfb5919-d564-4d6b-9ea2-29ea41ff72e8");
        fixture.Server["objectClass"] = ["top", "person", "user", leafClass.ToUpperInvariant()];
        fixture.Server["objectGUID"] = [identity.ToByteArray()];
        fixture.Server["sAMAccountName"] = ["offline-account"];
        fixture.Server["description"] = ["loaded description"];

        using var principal = Assert.IsAssignableFrom<Principal>(Principal.Materialize(fixture.Context, typeof(Principal), fixture.Entry));

        Assert.Equal(expectedType, principal.GetType());
        Assert.Equal(identity, principal.Guid);
        Assert.Equal("CN=item,DC=example,DC=test", principal.DistinguishedName);
        Assert.Equal("offline-account", principal.SamAccountName);
        Assert.Equal("loaded description", principal.Description);
        Assert.Equal("S-1-5-21-1-2-3-1001", principal.Sid!.Value);
        Assert.Same(fixture.Context, principal.Context);
        Assert.Same(fixture.Entry, principal.GetUnderlyingObject());
        Assert.Single(fixture.Reads);
        Assert.Empty(fixture.Writes);

        principal.Dispose();
        Assert.True(fixture.Entry.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => _ = principal.Description);
        // A materialized principal owns its entry, while the caller owns context.
        using var nextQuery = new UserPrincipal(fixture.Context);
        using var nextSearcher = new PrincipalSearcher(nextQuery);
        Assert.Same(fixture.Context, nextSearcher.Context);
        Assert.NotNull(nextSearcher.GetUnderlyingSearcher());
    }

    [Theory]
    [InlineData(typeof(UserPrincipal))]
    [InlineData(typeof(GroupPrincipal))]
    [InlineData(typeof(ComputerPrincipal))]
    public void Typed_materialization_retains_principal_scalar_cache_when_underlying_entry_is_reopened(Type type)
    {
        using var fixture = new Fixture();
        fixture.Server["description"] = ["before"];
        using var principal = Principal.Materialize(fixture.Context, type, fixture.Entry)!;
        Assert.Equal("before", principal.Description);
        Assert.Single(fixture.Reads);

        fixture.Server["description"] = ["after"];
        Assert.Equal("before", principal.Description);
        Assert.Single(fixture.Reads);
        fixture.Entry.Close();
        Assert.Equal("before", principal.Description);
        Assert.Equal("after", fixture.Entry.Properties["description"].Value);
        Assert.Equal(2, fixture.Reads.Count);
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Nonprincipal_directory_object_is_not_materialized_as_a_user()
    {
        using var fixture = new Fixture();
        fixture.Server["objectClass"] = ["top", "person", "contact"];
        Assert.Null(Principal.Materialize(fixture.Context, typeof(Principal), fixture.Entry));
        Assert.False(fixture.Entry.IsDisposed);
        Assert.Empty(fixture.Writes);
    }

    [Fact]
    public void Principal_projection_defers_entry_reads_until_current_is_requested()
    {
        using var fixture = new Fixture();
        using var results = new PrincipalSearchResult<Principal>(1,
            _ => Principal.Materialize(fixture.Context, typeof(UserPrincipal), fixture.Entry)!);
        using var cursor = results.GetEnumerator();
        Assert.Empty(fixture.Reads);
        Assert.Throws<InvalidOperationException>(() => _ = cursor.Current);
        Assert.True(cursor.MoveNext());
        Assert.Empty(fixture.Reads);
        using var principal = cursor.Current;
        Assert.IsType<UserPrincipal>(principal);
        Assert.Single(fixture.Reads);
        Assert.False(cursor.MoveNext());
        Assert.Throws<InvalidOperationException>(() => _ = cursor.Current);
        Assert.Single(fixture.Reads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Rejected_scalar_save_retains_edit_until_retry_or_explicit_cancellation(bool cancel)
    {
        using var fixture = new Fixture();
        fixture.Server["description"] = ["original"];
        using var user = fixture.Attach(new UserPrincipal(fixture.Context));
        user.Description = "requested";
        fixture.Fail = true;
        Assert.Throws<InvalidOperationException>(() => user.Save());
        Assert.Equal("original", Assert.Single(fixture.Server["description"]));
        Assert.Equal("requested", user.Description);
        Assert.Empty(fixture.Writes);

        if (cancel) user.Description = "original";
        fixture.Fail = false;
        user.Save();
        Assert.Equal(cancel ? "original" : "requested", Assert.Single(fixture.Server["description"]));
        var write = Assert.Single(fixture.Writes);
        var modification = Assert.Single(write.Modifications.Cast<System.DirectoryServices.Protocols.DirectoryAttributeModification>());
        Assert.Equal("description", modification.Name);
        Assert.Equal(cancel ? "original" : "requested", Assert.Single(modification.Cast<object>()));
    }

    [Fact]
    public void Acknowledged_scalar_save_does_not_overwrite_external_change_on_unrelated_save()
    {
        using var fixture = new Fixture();
        using var user = fixture.Attach(new UserPrincipal(fixture.Context));
        user.Description = "first";
        user.Save();
        fixture.Server["description"] = ["external"];
        user.DisplayName = "next";
        user.Save();
        Assert.Equal("external", Assert.Single(fixture.Server["description"]));
        Assert.Equal("next", Assert.Single(fixture.Server["displayName"]));
        Assert.DoesNotContain(fixture.Writes[1].Modifications.Cast<System.DirectoryServices.Protocols.DirectoryAttributeModification>(),
            modification => modification.Name.Equals("description", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FindOne_restores_caller_size_limit_when_underlying_search_throws_regression()
    {
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        using var query = new UserPrincipal(context);
        using var principalSearcher = new PrincipalSearcher(query);
        var searcher = Assert.IsType<DirectorySearcher>(principalSearcher.GetUnderlyingSearcher());
        InstallSearchTransport(searcher.SearchRoot!);
        searcher.SizeLimit = 37;
        var failure = new InvalidOperationException("controlled search configuration failure");
        searcher.ConfigureConnectionOverride = _ => throw failure;

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => principalSearcher.FindOne()));
        // FindOne's temporary limit must not alter subsequent FindAll behavior.
        Assert.Equal(37, searcher.SizeLimit);
    }
}
