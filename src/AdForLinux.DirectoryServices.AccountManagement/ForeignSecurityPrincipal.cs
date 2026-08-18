using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Store-local representation of an AD foreignSecurityPrincipal. Microsoft can
/// resolve these to the principal in the trusted forest; when that is not
/// possible it still returns a SID-bearing Principal rather than dropping the
/// group member.
/// </summary>
internal sealed class ForeignSecurityPrincipal : Principal
{
    internal ForeignSecurityPrincipal(PrincipalContext context, DirectoryEntry entry)
    {
        AttachExisting(context, entry);
    }

    private protected override string CreateObjectClass => "foreignSecurityPrincipal";

    internal override string CategoryFilter => "(objectClass=foreignSecurityPrincipal)";
}
