using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;

namespace AdForLinux.DirectoryServices.AccountManagement;

// Read-only evidence, not a reusable authorization ticket. No entry, context,
// connection, resolver, credential or pending descriptor is retained here.
internal sealed record CrossContextSavePlan(Guid DomainGuid, string DomainSid,
    Guid ObjectGuid, string ObjectSid, string SourceDn, string ReplicaDn,
    Guid ContainerGuid, string ContainerDn, string CurrentRdn, string? PendingName)
{
    internal const string ExecutionBoundary = "Cross-context Save preflight succeeded, but execution is not enabled: " +
        "identity-safe destination ModifyDN/Modify addressing, uncertain-write quarantine and retained-wrapper " +
        "authority rebinding require validation. No write was sent; pending edits and the source binding are retained.";

    internal static CrossContextSavePlan Prepare(PrincipalContext source, PrincipalContext destination,
        DirectoryEntry entry, Guid? retainedObjectGuid, string containerDn, string? pendingName)
    {
        using var sourceRoot = source.CreateDirectoryEntry(source.DefaultNamingContext);
        if (!entry.HasSameConnectionContext(sourceRoot))
            throw new InvalidOperationException("The retained entry no longer uses its principal context's authority.");
        var sourceDomain = Read(source, source.DefaultNamingContext, "(objectClass=domainDNS)", SearchScope.Base);
        var destinationDomain = Read(destination, destination.DefaultNamingContext, "(objectClass=domainDNS)", SearchScope.Base);
        var domainGuid = GuidValue(sourceDomain);
        var domainSid = SidValue(sourceDomain);
        if (GuidValue(destinationDomain) != domainGuid || SidValue(destinationDomain) != domainSid)
            throw new InvalidOperationException("The endpoints did not prove the same domain GUID and SID.");
        var original = Read(source, entry.DistinguishedName, "(objectClass=*)", SearchScope.Base);
        var objectGuid = GuidValue(original);
        var objectSid = SidValue(original);
        if (retainedObjectGuid is null || retainedObjectGuid == Guid.Empty || retainedObjectGuid != objectGuid
            || entry.Guid != objectGuid || entry.Properties["objectSid"].Value is not byte[] retainedSid
            || new SecurityIdentifier(retainedSid, 0).Value != objectSid)
            throw new InvalidOperationException("Fresh source identity does not match the retained entry identity.");
        if (new SecurityIdentifier(objectSid).AccountDomainSid?.Value != domainSid)
            throw new InvalidOperationException("The source object's account domain does not match the verified domain.");
        var replica = Read(destination, destination.DefaultNamingContext,
            "(objectGUID=" + LdapFilter.EscapeBytes(objectGuid.ToByteArray()) + ")", SearchScope.Subtree);
        if (GuidValue(replica) != objectGuid || SidValue(replica) != objectSid)
            throw new InvalidOperationException("The destination replica did not prove the same object GUID and SID.");
        var container = Read(destination, containerDn, "(objectClass=*)", SearchScope.Base);
        var actualContainer = Text(container, "distinguishedName");
        if (!Within(actualContainer, destination.DefaultNamingContext))
            throw new InvalidOperationException("The destination container is outside the verified naming context.");
        return new(domainGuid, domainSid, objectGuid, objectSid, Text(original, "distinguishedName"),
            Text(replica, "distinguishedName"), GuidValue(container), actualContainer,
            LdapDistinguishedName.RelativeName(Text(replica, "distinguishedName")), pendingName);
    }

    private static bool Within(string dn, string namingContext)
    {
        for (string? current = dn; current is not null; current = LdapDistinguishedName.Parent(current))
            if (current.Equals(namingContext, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static ResultPropertyCollection Read(PrincipalContext context, string dn, string filter, SearchScope scope)
    {
        using var root = context.CreateDirectoryEntry(dn);
        root.Options.Referral = ReferralChasingOption.None;
        using var searcher = new DirectorySearcher(root, filter,
            new[] { "objectGUID", "objectSid", "distinguishedName" }, scope)
        { ReferralChasing = ReferralChasingOption.None };
        using var results = context.SearchSaveContextEntries(searcher);
        var entries = results.Cast<SearchResult>().ToArray();
        if (entries.Length != 1)
            throw new InvalidOperationException("Cross-context preflight requires exactly one visible entry for each identity proof; replication lag or missing access is not success.");
        return entries[0].Snapshot().Properties;
    }

    private static object Value(ResultPropertyCollection values, string name) => values[name].Count == 1
        ? values[name][0]! : throw new InvalidOperationException("Cross-context identity evidence is missing or ambiguous: " + name);
    private static string Text(ResultPropertyCollection values, string name) => Value(values, name) is string text && text.Length > 0
        ? text : throw new InvalidOperationException("Cross-context identity text is invalid: " + name);
    private static Guid GuidValue(ResultPropertyCollection values) => Value(values, "objectGUID") is byte[] { Length: 16 } bytes
        && new Guid(bytes) is var guid && guid != Guid.Empty ? guid
        : throw new InvalidOperationException("Cross-context objectGUID evidence is invalid.");
    private static string SidValue(ResultPropertyCollection values) => Value(values, "objectSid") is byte[] bytes
        ? new SecurityIdentifier(bytes, 0).Value : throw new InvalidOperationException("Cross-context SID evidence is invalid.");
}
