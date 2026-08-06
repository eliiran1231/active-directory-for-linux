namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>How widely a group can be used. Values match Microsoft.</summary>
public enum GroupScope
{
    /// <summary>Local to one domain. Members can come from any domain.</summary>
    Local = 0,

    /// <summary>Global: members from its own domain, usable across the forest.</summary>
    Global = 1,

    /// <summary>Universal: members and use anywhere in the forest.</summary>
    Universal = 2,
}
