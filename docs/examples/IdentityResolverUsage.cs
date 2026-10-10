using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.Security.Principal;

namespace AdForLinux.Examples;

// Compiled by the companion consumer, which has no core friend access.
public static class IdentityResolverUsage
{
    public static DirectoryIdentityResolver FromEntry(DirectoryEntry entry) => DirectoryIdentityResolver.ForEntry(entry);
    public static DirectoryIdentityResolver FromContext(PrincipalContext context) => context.CreateIdentityResolver();
    public static SecurityIdentifier ResolveName(DirectoryEntry entry, NTAccount name)
        => (SecurityIdentifier)FromEntry(entry).Translate(name, typeof(SecurityIdentifier));
    public static NTAccount ResolveSid(PrincipalContext context, SecurityIdentifier sid)
        => (NTAccount)FromContext(context).Translate(sid, typeof(NTAccount));
    public static IdentityReferenceCollection ResolveAvailableNames(DirectoryIdentityResolver resolver, IdentityReferenceCollection identities)
        => resolver.Translate(identities, typeof(NTAccount));
    public static IdentityReferenceCollection ResolveAllNames(DirectoryIdentityResolver resolver, IdentityReferenceCollection identities)
        => resolver.Translate(identities, typeof(NTAccount), forceSuccess: true);
}
