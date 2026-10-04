using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class Issue216RegressionTests
{
    [Fact]
    public void Subsecond_configured_paging_limit_is_unlimited()
    {
        var budget = new ServerSearchTimeLimitBudget(TimeSpan.FromMilliseconds(500),
            TimeSpan.FromSeconds(-1), true, TimeProvider.System);
        var request = new System.DirectoryServices.Protocols.SearchRequest();
        Assert.True(budget.TryApply(request));
        Assert.Equal(TimeSpan.Zero, request.TimeLimit);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Cached_cursor_resets_and_replayed_binary_values_are_independent(bool streaming)
    {
        using var root = new DirectoryEntry("LDAP://offline.invalid/CN=test");
        var properties = new ResultPropertyCollection();
        properties.Set("adspath", new object[] { root.Path });
        properties.Set("objectGUID", new object[] { new byte[] { 1, 2, 3 } });
        var row = new SearchResult(root, properties);
        using var results = streaming
            ? new SearchResultCollection(new[] { row }.Select(item => item), true)
            : new SearchResultCollection(new[] { row });
        var cursor = results.GetEnumerator();
        Assert.Throws<InvalidOperationException>(() => cursor.Current);
        Assert.True(cursor.MoveNext());
        var first = (byte[])((SearchResult)cursor.Current).Properties["objectGUID"][0]!;
        first[0] = 99;
        Assert.False(cursor.MoveNext());
        Assert.Throws<InvalidOperationException>(() => cursor.Current);
        cursor.Reset();
        Assert.Throws<InvalidOperationException>(() => cursor.Current);
        Assert.True(cursor.MoveNext());
        var replay = (byte[])((SearchResult)cursor.Current).Properties["objectGUID"][0]!;
        Assert.Equal(new byte[] { 1, 2, 3 }, replay);
        Assert.NotSame(first, replay);
    }

    [Fact]
    public void Projected_principal_cursors_share_rows_but_not_returned_wrappers()
    {
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        using var results = new PrincipalSearchResult<Principal>(2,
            index => new UserPrincipal(context) { Name = index.ToString() });
        using var firstCursor = results.GetEnumerator();
        using var secondCursor = results.GetEnumerator();
        Assert.True(firstCursor.MoveNext());
        using var first = firstCursor.Current;
        using var sameRow = firstCursor.Current;
        Assert.NotSame(first, sameRow);
        first.Dispose();
        Assert.Equal("0", sameRow.Name);
        Assert.True(firstCursor.MoveNext());
        Assert.True(secondCursor.MoveNext());
        using var sharedRow = firstCursor.Current;
        Assert.Equal("0", sharedRow.Name);
    }

    [Fact]
    public void Retained_service_names_and_positioned_member_cursor_survive_owner_disposal()
    {
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        using var computer = new ComputerPrincipal(context);
        var names = computer.ServicePrincipalNames;
        computer.Dispose();
        names.Add("HOST/test");
        Assert.Equal("HOST/test", Assert.Single(names));
        using var group = new GroupPrincipal(context);
        using var user = new UserPrincipal(context);
        group.Members.Add(user);
        using var cursor = group.Members.GetEnumerator();
        Assert.True(cursor.MoveNext());
        group.Dispose();
        Assert.Same(user, cursor.Current);
        cursor.Reset();
        Assert.Throws<ObjectDisposedException>(() => group.Members);
    }
}
