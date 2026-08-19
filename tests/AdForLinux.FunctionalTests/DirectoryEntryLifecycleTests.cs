using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public class DirectoryEntryLifecycleTests
{
    private const string Path = "LDAP://127.0.0.1:1/DC=example,DC=test";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Close_and_dispose_prevent_a_new_connection(bool close)
    {
        var entry = new DirectoryEntry(Path, "user@example.test", "password", AuthenticationTypes.None);

        if (close)
        {
            entry.Close();
        }
        else
        {
            entry.Dispose();
        }

        var exception = Assert.Throws<ObjectDisposedException>(() => entry.GetConnection());

        Assert.Equal(nameof(DirectoryEntry), exception.ObjectName);
        Assert.Throws<ObjectDisposedException>(() => entry.GetSchemaConnection());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Bind_backed_members_throw_after_close_or_dispose(bool close)
    {
        var entry = new DirectoryEntry(Path, "user@example.test", "password", AuthenticationTypes.None);
        using var searcher = new DirectorySearcher(entry);
        using var otherEntry = new DirectoryEntry(Path, "user@example.test", "password", AuthenticationTypes.None);

        if (close)
        {
            entry.Close();
        }
        else
        {
            entry.Dispose();
        }

        Action[] operations =
        {
            entry.RefreshCache,
            () => entry.RefreshCache(Array.Empty<string>()),
            entry.CommitChanges,
            () => _ = entry.Properties["distinguishedName"].Value,
            () => _ = entry.Name,
            () => _ = entry.SchemaClassName,
            () => _ = entry.Guid,
            () => _ = entry.NativeGuid,
            () => _ = entry.NativeObject,
            () => _ = entry.Parent,
            () => _ = entry.SchemaEntry,
            () => _ = entry.Options,
            () => entry.Children.Add("CN=child", "user"),
            () => entry.Children.Find("CN=child"),
            () => entry.Children.Remove(otherEntry),
            () => entry.Children.GetEnumerator().MoveNext(),
            () => searcher.FindOne(),
            entry.DeleteTree,
            () => entry.Rename("CN=renamed"),
            () => entry.MoveTo(otherEntry),
            () => entry.CopyTo(otherEntry),
            () => entry.Invoke("method"),
            () => entry.InvokeGet("property"),
            () => entry.InvokeSet("property", "value"),
        };

        foreach (var operation in operations)
        {
            var exception = Assert.Throws<ObjectDisposedException>(operation);
            Assert.Equal(nameof(DirectoryEntry), exception.ObjectName);
        }
    }

    [Fact]
    public void Repeated_disposal_is_harmless_and_local_state_remains_readable()
    {
        var entry = new DirectoryEntry(Path, "user@example.test", "password", AuthenticationTypes.None);

        entry.Dispose();
        entry.Dispose();
        entry.Close();

        Assert.Equal(Path, entry.Path);
        Assert.Equal("user@example.test", entry.Username);
        Assert.Equal(AuthenticationTypes.None, entry.AuthenticationType);
        Assert.True(entry.UsePropertyCache);
        Assert.Equal("DC=example,DC=test", entry.DistinguishedName);
        Assert.NotNull(entry.Children);
    }

    [Fact]
    public void Disposed_exception_uses_the_runtime_type_name()
    {
        var entry = new DerivedDirectoryEntry(Path);
        entry.Dispose();

        var exception = Assert.Throws<ObjectDisposedException>(entry.RefreshCache);

        Assert.Equal(nameof(DerivedDirectoryEntry), exception.ObjectName);
    }

    private sealed class DerivedDirectoryEntry : DirectoryEntry
    {
        public DerivedDirectoryEntry(string path)
            : base(path)
        {
        }
    }
}
