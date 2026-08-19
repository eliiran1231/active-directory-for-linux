using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryLifecycleTests
{
    private const string UnreachablePath = "LDAP://127.0.0.1:1/DC=example,DC=test";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Close_and_dispose_prevent_new_bind_operations(bool close)
    {
        var entry = new DirectoryEntry(UnreachablePath, null, null, AuthenticationTypes.Anonymous);
        var children = entry.Children;
        var childEnumerator = children.GetEnumerator();

        if (close)
        {
            entry.Close();
        }
        else
        {
            entry.Dispose();
        }

        AssertDisposed(entry, entry.RefreshCache);
        AssertDisposed(entry, () => entry.RefreshCache(Array.Empty<string>()));
        AssertDisposed(entry, entry.CommitChanges);
        AssertDisposed(entry, entry.DeleteTree);
        AssertDisposed(entry, () => _ = entry.SchemaClassName);
        AssertDisposed(entry, () => entry.GetSchemaConnection());
        AssertDisposed(entry, () => entry.Rename("CN=renamed"));
        AssertDisposed(entry, () => _ = entry.Parent);
        AssertDisposed(entry, () => children.Add("CN=child", "user"));
        AssertDisposed(entry, () => children.Find("CN=child"));
        AssertDisposed(entry, () => children.GetEnumerator());
        AssertDisposed(entry, () => childEnumerator.MoveNext());

        using var searcher = new DirectorySearcher(entry);
        AssertDisposed(entry, () => searcher.FindOne());
        AssertDisposed(entry, () => searcher.FindAll());

        // These values are stored locally and remain readable in Microsoft's implementation.
        Assert.Equal(UnreachablePath, entry.Path);
        Assert.Equal(AuthenticationTypes.Anonymous, entry.AuthenticationType);
        Assert.Null(entry.Username);
        Assert.True(entry.UsePropertyCache);

        // Repeated lifecycle calls remain harmless.
        entry.Close();
        entry.Dispose();
    }

    [Fact]
    public void Disposing_a_cached_new_entry_invalidates_entry_cache_and_pending_mutations()
    {
        using var parent = new DirectoryEntry(UnreachablePath, null, null, AuthenticationTypes.Anonymous);
        var child = parent.Children.Add("CN=child", "user");
        var cachedProperties = child.Properties;
        Assert.Equal("user", cachedProperties["objectClass"].Value);

        child.Dispose();

        AssertDisposed(child, () => _ = child.Properties["objectClass"].Value);
        AssertDisposed(child, () => cachedProperties["description"].Value = "changed");
        AssertDisposed(child, child.CommitChanges);
    }

    private static void AssertDisposed(DirectoryEntry entry, Action action)
    {
        var exception = Assert.Throws<ObjectDisposedException>(action);
        Assert.Equal(entry.GetType().Name, exception.ObjectName);
    }
}
