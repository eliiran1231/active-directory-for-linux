using AdForLinux.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryLifecycleTests
{
    private const string UnreachablePath = "LDAP://127.0.0.1:1/DC=example,DC=test";

    [Fact]
    public void Dispose_prevents_new_bind_operations()
    {
        var entry = new DirectoryEntry(UnreachablePath, null, null, AuthenticationTypes.Anonymous);
        var children = entry.Children;
        var childEnumerator = children.GetEnumerator();

        entry.Dispose();

        AssertDisposed(entry, entry.RefreshCache);
        AssertDisposed(entry, () => entry.RefreshCache(Array.Empty<string>()));
        entry.CommitChanges();
        AssertDisposed(entry, entry.DeleteTree);
        AssertDisposed(entry, () => _ = entry.SchemaClassName);
        AssertDisposed(entry, () => _ = entry.SchemaEntry);
        AssertDisposed(entry, () => entry.GetSchemaConnection());
        AssertDisposed(entry, () => entry.Rename(null));
        AssertDisposed(entry, () => entry.Rename("CN=renamed"));
        AssertDisposed(entry, () => _ = entry.Name);
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
    public void Close_is_non_terminal_and_later_bind_is_attempted()
    {
        using var entry = new DirectoryEntry(
            UnreachablePath,
            null,
            null,
            AuthenticationTypes.Anonymous);

        entry.Close();
        entry.Close();

        // A disposed entry would throw ObjectDisposedException before trying LDAP.
        // Close instead leaves the entry reusable, so this reaches the deliberately
        // unavailable endpoint while attempting a new bind.
        Assert.Throws<COMException>(entry.RefreshCache);

        entry.Dispose();
        AssertDisposed(entry, entry.RefreshCache);
    }

    [Fact]
    public void Close_releases_connections_and_rebinds_on_later_access()
    {
        using var entry = Open(TestSettings.AdministratorDn);

        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
        var originalConnection = entry.GetConnection();
        var originalSchemaConnection = entry.GetSchemaConnection();

        entry.Close();

        AssertConnectionDisposed(originalConnection);
        AssertConnectionDisposed(originalSchemaConnection);

        entry.RefreshCache();
        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
        Assert.NotSame(originalConnection, entry.GetConnection());
        Assert.NotSame(originalSchemaConnection, entry.GetSchemaConnection());

        // Repeated Close calls remain harmless and the entry can bind yet again.
        entry.Close();
        entry.Close();
        Assert.Equal("Administrator", entry.Properties["sAMAccountName"].Value);
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
        child.CommitChanges();
    }

    private static void AssertDisposed(DirectoryEntry entry, Action action)
    {
        var exception = Assert.Throws<ObjectDisposedException>(action);
        Assert.Equal(entry.GetType().Name, exception.ObjectName);
    }

    private static DirectoryEntry Open(string distinguishedName) =>
        new(TestSettings.PathFor(distinguishedName), TestSettings.BindDn, TestSettings.BindPassword,
            AuthenticationTypes.SecureSocketsLayer);

    private static void AssertConnectionDisposed(LdapConnection connection)
    {
        var request = new SearchRequest(
            string.Empty,
            "(objectClass=*)",
            System.DirectoryServices.Protocols.SearchScope.Base,
            "1.1");
        Assert.Throws<ObjectDisposedException>(() => connection.SendRequest(request));
    }
}
