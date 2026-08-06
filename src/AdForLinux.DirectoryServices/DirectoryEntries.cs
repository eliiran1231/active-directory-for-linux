using System.Collections;

namespace AdForLinux.DirectoryServices;

/// <summary>
/// The children of a <see cref="DirectoryEntry"/>, like Microsoft's
/// <c>DirectoryEntries</c>. Use <see cref="Add"/> to create a child and
/// <see cref="Remove"/> to delete one.
/// </summary>
public sealed class DirectoryEntries : IEnumerable<DirectoryEntry>
{
    private readonly DirectoryEntry _parent;

    internal DirectoryEntries(DirectoryEntry parent)
    {
        _parent = parent;
    }

    /// <summary>
    /// Makes a new, unsaved child object, e.g. <c>Add("CN=Jeff", "user")</c>.
    /// Set its properties, then call <c>CommitChanges</c> to create it.
    /// </summary>
    public DirectoryEntry Add(string name, string schemaClassName) =>
        DirectoryEntry.NewChild(_parent, name, schemaClassName);

    /// <summary>Deletes a child object and its subtree.</summary>
    public void Remove(DirectoryEntry child) => child.DeleteTree();

    public IEnumerator<DirectoryEntry> GetEnumerator()
    {
        using var searcher = new DirectorySearcher(_parent, "(objectClass=*)")
        {
            SearchScope = SearchScope.OneLevel,
        };

        foreach (var result in searcher.FindAll())
        {
            yield return result.GetDirectoryEntry();
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
