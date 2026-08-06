namespace AdForLinux.DirectoryServices;

/// <summary>How deep a <see cref="DirectorySearcher"/> looks. Matches Microsoft.</summary>
public enum SearchScope
{
    /// <summary>Just the base object.</summary>
    Base = 0,

    /// <summary>The base object's immediate children.</summary>
    OneLevel = 1,

    /// <summary>The base object and its whole subtree. The default.</summary>
    Subtree = 2,
}
