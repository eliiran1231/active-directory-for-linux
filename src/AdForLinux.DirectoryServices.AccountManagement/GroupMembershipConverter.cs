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

    /// <summary>
    /// Normalizes the well-known DN form used for store-local FSP objects
    /// without binding to every group member merely to inspect objectClass.
    /// AD names an FSP after its SDDL SID and stores it directly below the
    /// ForeignSecurityPrincipals container.
    /// </summary>
    internal static string ForStoredDistinguishedName(string distinguishedName)
    {
        const string cnPrefix = "CN=";
        const string fspContainer = "CN=ForeignSecurityPrincipals";
        if (!distinguishedName.StartsWith(cnPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return distinguishedName;
        }

        var firstComma = distinguishedName.IndexOf(',');
        if (firstComma <= cnPrefix.Length)
        {
            return distinguishedName;
        }

        var secondComma = distinguishedName.IndexOf(',', firstComma + 1);
        var parentRdn = secondComma < 0
            ? distinguishedName[(firstComma + 1)..]
            : distinguishedName[(firstComma + 1)..secondComma];
        if (!parentRdn.Equals(fspContainer, StringComparison.OrdinalIgnoreCase))
        {
            return distinguishedName;
        }

        try
        {
            return ToSidBinding(SidCodec.Parse(
                distinguishedName[cnPrefix.Length..firstComma]));
        }
        catch (ArgumentException)
        {
            // A malformed/nonstandard DN is not safe to reinterpret. Leave it
            // unchanged and let the normal directory materialization path act.
            return distinguishedName;
        }
    }
}
