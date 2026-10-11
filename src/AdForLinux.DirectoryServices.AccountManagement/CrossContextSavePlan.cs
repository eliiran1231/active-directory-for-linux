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
        // Stable lock ordering is used only for short captures/publication, never I/O.
        var owners = new[] { (source.IdentityLifetime, (Action)source.CheckDisposed),
            (destination.IdentityLifetime, (Action)destination.CheckDisposed),
            (entry.IdentityLifetime, (Action)entry.ThrowIfDisposed) }
            .OrderBy(owner => owner.Item1.Id).ToArray();
        var generations = owners.Select(owner => owner.Item1.Capture(owner.Item2)).ToArray();
        T Checked<T>(Func<T> action, int index = 0) => index == owners.Length ? action()
            : owners[index].Item1.Checked(generations[index], owners[index].Item2, () => Checked(action, index + 1));
        void Validate() => Checked(() => true);

        var capture = Checked(() =>
        {
            using var sourceRoot = source.CreateDirectoryEntry(string.Empty);
            if (!entry.HasSameConnectionContext(sourceRoot))
                throw new InvalidOperationException("The retained entry no longer uses its principal context's authority.");
            var guid = GuidValue(entry.CachedIdentityValues("objectGUID"));
            var sid = SidValue(entry.CachedIdentityValues("objectSid"));
            if (retainedObjectGuid is null || retainedObjectGuid == Guid.Empty || retainedObjectGuid != guid)
                throw new InvalidOperationException("The retained entry does not match the attached principal identity.");
            return (Guid: guid, Sid: sid, Dn: entry.IdentityTarget,
                Source: source.BuildOptions(), Destination: destination.BuildOptions(),
                OpenSource: source.SaveContextSessionFactory, OpenDestination: destination.SaveContextSessionFactory);
        });
        if (capture.Source.Port is 3268 or 3269 || capture.Destination.Port is 3268 or 3269)
            throw new NotSupportedException("Cross-context preflight requires domain endpoints, not Global Catalog endpoints.");
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        var timeout = capture.Source.Timeout < capture.Destination.Timeout ? capture.Source.Timeout : capture.Destination.Timeout;
        Validate();
        using var sourceSession = capture.OpenSource(capture.Source);
        Validate();
        using var destinationSession = capture.OpenDestination(capture.Destination);
        Validate();

        IdentitySearchRow Read(CrossContextSaveSession session, string dn, string filter,
            System.DirectoryServices.Protocols.SearchScope scope, params string[] attributes)
        {
            Validate();
            var remaining = timeout - deadline.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Cross-context preflight deadline expired.");
            var request = new System.DirectoryServices.Protocols.SearchRequest(dn, filter, scope, attributes)
            {
                SizeLimit = 2, TimeLimit = remaining,
                Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Never
            };
            if (scope == System.DirectoryServices.Protocols.SearchScope.Subtree)
                request.Controls.Add(new System.DirectoryServices.Protocols.DirectoryControl(
                    AdIdentityLookup.DomainScopeControl, null, true, true));
            var response = session.Search(request, remaining);
            Validate();
            if (deadline.Elapsed >= timeout) throw new TimeoutException("Cross-context preflight deadline expired.");
            if (response.ResultCode != System.DirectoryServices.Protocols.ResultCode.Success
                || response.References.Count != 0 || response.Referral.Length != 0 || response.Entries.Count != 1)
                throw new InvalidOperationException("Cross-context preflight requires a complete, unreferred, unique successful response.");
            var row = response.Entries[0];
            var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in row.Attributes.AttributeNames)
                values[name] = row.Attributes[name].GetValues(
                    name.Equals("objectGUID", StringComparison.OrdinalIgnoreCase) || name.Equals("objectSid", StringComparison.OrdinalIgnoreCase)
                        ? typeof(byte[]) : typeof(string));
            return new IdentitySearchRow(values, row.DistinguishedName);
        }
        const System.DirectoryServices.Protocols.SearchScope Base = System.DirectoryServices.Protocols.SearchScope.Base;
        const System.DirectoryServices.Protocols.SearchScope Subtree = System.DirectoryServices.Protocols.SearchScope.Subtree;
        string Domain(CrossContextSaveSession session)
        {
            var root = Read(session, string.Empty, "(objectClass=*)", Base,
                "defaultNamingContext", "configurationNamingContext", "namingContexts", "supportedControl");
            return AdIdentityDomainMetadata.ValidateRoot([root]).Domain;
        }
        IdentitySearchRow Member(CrossContextSaveSession session, string domain, string filter)
            => Read(session, domain, filter, Subtree, "objectGUID", "objectSid", "distinguishedName");
        string DnFilter(string dn) => "(distinguishedName=" + AdIdentityLookup.EscapeText(dn) + ")";
        string GuidFilter(Guid guid) => "(objectGUID=" + LdapFilter.EscapeBytes(guid.ToByteArray()) + ")";
        var sourceNc = Domain(sourceSession);
        var destinationNc = Domain(destinationSession);
        var sourceDomain = Read(sourceSession, sourceNc, "(objectClass=domainDNS)", Base, "objectGUID", "objectSid");
        var destinationDomain = Read(destinationSession, destinationNc, "(objectClass=domainDNS)", Base, "objectGUID", "objectSid");
        var domainGuid = GuidValue(sourceDomain.Values("objectGUID"));
        var domainSid = SidValue(sourceDomain.Values("objectSid"));
        if (GuidValue(destinationDomain.Values("objectGUID")) != domainGuid || SidValue(destinationDomain.Values("objectSid")) != domainSid)
            throw new InvalidOperationException("The endpoints did not prove the same domain GUID and SID.");
        // Starting at the verified NC with the critical domain-scope control is
        // the membership proof. A base search or textual DN suffix is not proof:
        // a subordinate application NC can have the same suffix.
        var original = Member(sourceSession, sourceNc, DnFilter(capture.Dn));
        var objectGuid = GuidValue(original.Values("objectGUID"));
        var objectSid = SidValue(original.Values("objectSid"));
        if (objectGuid != capture.Guid || objectSid != capture.Sid)
            throw new InvalidOperationException("Fresh source identity does not match the retained entry identity.");
        if (new SecurityIdentifier(objectSid).AccountDomainSid?.Value != domainSid)
            throw new InvalidOperationException("The source object's account domain does not match the verified domain.");
        var replica = Member(destinationSession, destinationNc, GuidFilter(objectGuid));
        if (GuidValue(replica.Values("objectGUID")) != objectGuid || SidValue(replica.Values("objectSid")) != objectSid)
            throw new InvalidOperationException("The destination replica did not prove the same object GUID and SID.");
        var container = Member(destinationSession, destinationNc, DnFilter(containerDn));
        var plan = new CrossContextSavePlan(domainGuid, domainSid, objectGuid, objectSid, Dn(original),
            Dn(replica), GuidValue(container.Values("objectGUID")), Dn(container),
            LdapDistinguishedName.RelativeName(Dn(replica)), pendingName);
        return Checked(() =>
        {
            // Cached identity can be edited without a binding-generation change.
            if (entry.IdentityTarget != capture.Dn || GuidValue(entry.CachedIdentityValues("objectGUID")) != capture.Guid
                || SidValue(entry.CachedIdentityValues("objectSid")) != capture.Sid)
                throw new InvalidOperationException("Retained identity changed during preflight.");
            return plan;
        });
    }

    private static string Dn(IdentitySearchRow row) => row.Text("distinguishedName") is { Length: > 0 } dn
        && !string.IsNullOrWhiteSpace(row.DistinguishedName)
        && string.Equals(dn, row.DistinguishedName, StringComparison.OrdinalIgnoreCase) ? dn
        : throw new InvalidOperationException("Cross-context distinguishedName evidence is missing or inconsistent.");
    private static Guid GuidValue(object[] values) => values is [byte[] { Length: 16 } bytes]
        && new Guid(bytes) is var guid && guid != Guid.Empty ? guid
        : throw new InvalidOperationException("Cross-context objectGUID evidence is invalid.");
    private static string SidValue(object[] values)
    {
        if (values is not [byte[] bytes]) throw new InvalidOperationException("Cross-context SID evidence is invalid.");
        var sid = new SecurityIdentifier(bytes, 0);
        if (sid.BinaryLength != bytes.Length) throw new InvalidOperationException("Cross-context SID encoding is invalid.");
        return sid.Value;
    }
}
