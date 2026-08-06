namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The kind of store a <see cref="PrincipalContext"/> talks to. Matches
/// Microsoft. This Linux port supports <see cref="Domain"/>.
/// </summary>
public enum ContextType
{
    /// <summary>The local machine's SAM database. Not supported on Linux.</summary>
    Machine = 0,

    /// <summary>An Active Directory domain. Supported.</summary>
    Domain = 1,

    /// <summary>An AD LDS / ADAM store. Not supported yet.</summary>
    ApplicationDirectory = 2,
}
