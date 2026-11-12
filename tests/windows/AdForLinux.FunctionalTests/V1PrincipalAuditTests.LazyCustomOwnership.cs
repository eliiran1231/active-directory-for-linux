using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Deferred_custom_results_keep_the_captured_type_after_query_or_searcher_disposal(bool disposeSearcher)
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new MaterializedCustomUser(fixture.Context);
        using var searcher = fixture.Search(query);
        using var results = searcher.FindAll();
        var reads = fixture.Reads.Count;
        if (disposeSearcher) searcher.Dispose();
        else query.Dispose();
        Assert.Equal(reads, fixture.Reads.Count);
        using var cursor = results.GetEnumerator();
        Assert.True(cursor.MoveNext());
        Assert.Equal(reads, fixture.Reads.Count);
        using var principal = Assert.IsType<MaterializedCustomUser>(cursor.Current);
        Assert.Same(fixture.Context, principal.ConstructorContext);
        Assert.Equal(fixture.Identity, principal.Guid);
        Assert.Equal("found description", principal.Description);
        Assert.Same(fixture.Context, principal.Context);
        Assert.False(cursor.MoveNext());
        var entry = Assert.IsType<DirectoryEntry>(principal.GetUnderlyingObject());
        principal.Dispose();
        Assert.True(entry.IsDisposed);
        Assert.False(fixture.Context.SearchRoot.IsDisposed);
    }

    [Fact]
    public void Deferred_custom_result_cannot_construct_a_principal_after_its_context_is_disposed()
    {
        using var fixture = new PrincipalReadFixture();
        using var query = new MaterializedCustomUser(fixture.Context);
        using var searcher = fixture.Search(query);
        using var results = searcher.FindAll();
        using var cursor = results.GetEnumerator();
        Assert.True(cursor.MoveNext());
        var reads = fixture.Reads.Count;
        fixture.Context.Dispose();
        var failure = Assert.Throws<System.Reflection.TargetInvocationException>(() => _ = cursor.Current);
        Assert.IsType<ObjectDisposedException>(failure.InnerException);
        Assert.Equal(reads, fixture.Reads.Count);
    }
}
