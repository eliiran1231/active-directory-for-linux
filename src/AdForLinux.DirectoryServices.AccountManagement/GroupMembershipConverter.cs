namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Converts principals to the values accepted by AD's member attribute.</summary>
internal static class GroupMembershipConverter
{
    internal static string ForPrincipal(GroupPrincipal group, Principal member)
    {
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(member);

        var distinguishedName = member.DistinguishedName
            ?? throw new InvalidOperationException(
                "The principal must be saved before it can be used as a group member.");

        var sameForest = ReferenceEquals(group.Context, member.Context)
            || AreSameForest(
                group.Context.RootDomainNamingContext,
                member.Context.RootDomainNamingContext);
        return SelectValue(
            member is ForeignSecurityPrincipal,
            sameForest,
            distinguishedName,
            member.GetSidBytes());
    }

    internal static string SelectValue(
        bool isForeignSecurityPrincipal,
        bool sameForest,
        string distinguishedName,
        byte[]? sid)
    {
        ArgumentException.ThrowIfNullOrEmpty(distinguishedName);
        if (!isForeignSecurityPrincipal && sameForest)
        {
            return distinguishedName;
        }

        if (sid is null || sid.Length == 0)
        {
            throw new PrincipalOperationException(
                "The security identifier for the cross-forest group member could not be read.");
        }

        return ToSidBinding(sid);
    }

    internal static bool AreSameForest(string firstRootDomainDn, string secondRootDomainDn) =>
        firstRootDomainDn.Equals(secondRootDomainDn, StringComparison.OrdinalIgnoreCase);

    internal static string ToSidBinding(byte[] sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        return $"<SID={Convert.ToHexString(sid).ToLowerInvariant()}>";
    }
}
