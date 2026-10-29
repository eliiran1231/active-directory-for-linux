using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using System.DirectoryServices.Protocols;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.AccountManagement;

// Short-lived authority: owns both endpoint sessions, captured owners and the one
// deadline. Its data-only plan cannot be imported into a different operation.
internal sealed class CrossContextSaveOperation : IDisposable
{
    private readonly DirectoryEntry entry;
    private readonly (IdentityContextLifetime Lifetime, Action Validate)[] owners;
    private readonly long[] generations;
    private readonly TimeProvider clock;
    private readonly long started;
    private TimeSpan timeout = TimeSpan.MaxValue;
    private readonly Action? validateFrozen;
    private readonly object frozenGate;
    private readonly (Guid Guid, string Sid, string Dn, LdapConnectionOptions Source,
        LdapConnectionOptions Destination, Func<LdapConnectionOptions, CrossContextSaveSession> OpenSource,
        Func<LdapConnectionOptions, CrossContextSaveSession> OpenDestination) capture;
    private CrossContextSaveSession? sourceSession, destinationSession;
    private DirectoryEntry.CrossContextLease? lease;
    private bool disposed, prepared;
    internal LdapConnectionOptions DestinationOptions => capture.Destination.Clone();

    internal CrossContextSaveOperation(PrincipalContext source, PrincipalContext destination,
        DirectoryEntry entry, Guid? retainedObjectGuid, TimeProvider? timeProvider = null, Action? validateFrozen = null, object? frozenGate = null)
    {
        this.entry = entry; this.validateFrozen = validateFrozen; this.frozenGate = frozenGate ?? new object();
        clock = timeProvider ?? TimeProvider.System; started = clock.GetTimestamp();
        owners = new[] { (source.IdentityLifetime, (Action)source.CheckDisposed),
            (destination.IdentityLifetime, (Action)destination.CheckDisposed),
            (entry.IdentityLifetime, (Action)entry.ThrowIfDisposed) }.OrderBy(o => o.Item1.Id).ToArray();
        generations = owners.Select(o => o.Lifetime.Capture(o.Validate)).ToArray();
        capture = Checked(() =>
        {
            using var sourceRoot = source.CreateDirectoryEntry(string.Empty);
            if (!entry.HasSameConnectionContext(sourceRoot))
                throw new InvalidOperationException("The retained entry no longer uses its principal context's authority.");
            var guid = GuidValue(entry.CachedIdentityValues("objectGUID"));
            var sid = SidValue(entry.CachedIdentityValues("objectSid"));
            if (retainedObjectGuid is null || retainedObjectGuid == Guid.Empty || retainedObjectGuid != guid)
                throw new InvalidOperationException("The retained entry does not match the attached principal identity.");
            return (guid, sid, entry.IdentityTarget, source.BuildOptions(), destination.BuildOptions(),
                source.SaveContextSessionFactory, destination.SaveContextSessionFactory);
        });
        if (capture.Source.Port is 3268 or 3269 || capture.Destination.Port is 3268 or 3269)
            throw new NotSupportedException("Cross-context preflight requires domain endpoints, not Global Catalog endpoints.");
        timeout = capture.Source.Timeout < capture.Destination.Timeout ? capture.Source.Timeout : capture.Destination.Timeout;
    }

    internal T Checked<T>(Func<T> action, bool requireBudget = true)
    {
        if (disposed) throw new ObjectDisposedException(nameof(CrossContextSaveOperation));
        T Next(int index)
        {
            if (index == owners.Length)
            {
                lock (frozenGate)
                {
                    validateFrozen?.Invoke();
                    if (requireBudget) _ = Budget();
                    return action();
                }
            }
            var owner = owners[index];
            return ReferenceEquals(owner.Lifetime, entry.IdentityLifetime) && lease is not null
                ? entry.CheckedCrossContext(lease, () => Next(index + 1))
                : owner.Lifetime.Checked(generations[index], owner.Validate, () => Next(index + 1));
        }
        return Next(0);
    }
    private TimeSpan Budget()
    {
        var remaining = timeout - clock.GetElapsedTime(started);
        if (remaining <= TimeSpan.Zero) throw new TimeoutException("Cross-context operation deadline expired.");
        return remaining;
    }
    internal TimeSpan Remaining() => Checked(Budget);
    internal DirectoryEntry.CrossContextLease ReserveEntry() => Checked(() =>
        lease = entry.ReserveCrossContext(capture.Guid, capture.Sid));

    internal CrossContextSavePlan Prepare(string containerDn, string? pendingName,
        Func<LdapConnectionOptions, ICrossContextExecutorTransport>? openControlledDestination = null)
    {
        if (prepared) throw new InvalidOperationException("Preflight belongs to one operation and cannot be repeated.");
        prepared = true;
        if (openControlledDestination is null && capture.OpenSource == CrossContextSaveSession.DefaultFactory
            && capture.OpenDestination == CrossContextSaveSession.DefaultFactory)
        {
            using var deadline = new CancellationTokenSource(Remaining());
            var pair = LdapConnectionProvider.AcquirePair(capture.Source, capture.Destination, Remaining, deadline.Token);
            sourceSession = new CrossContextSaveSession(pair[0]);
            destinationSession = new CrossContextSaveSession(pair[1]);
        }
        else
        {
            // Explicitly injected test transports preserve their ownership contract.
            sourceSession = capture.OpenSource(capture.Source.Clone(Remaining()));
            _ = Remaining();
            destinationSession = openControlledDestination is null
                ? capture.OpenDestination(capture.Destination.Clone(Remaining()))
                : new CrossContextSaveSession(openControlledDestination(capture.Destination.Clone(Remaining())));
        }
        _ = Remaining();
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
        var sourceNc = Domain(sourceSession!);
        var destinationNc = Domain(destinationSession!);
        var sourceDomain = Read(sourceSession!, sourceNc, "(objectClass=domainDNS)", Base, "objectGUID", "objectSid");
        var destinationDomain = Read(destinationSession!, destinationNc, "(objectClass=domainDNS)", Base, "objectGUID", "objectSid");
        var domainGuid = GuidValue(sourceDomain.Values("objectGUID"));
        var domainSid = SidValue(sourceDomain.Values("objectSid"));
        if (GuidValue(destinationDomain.Values("objectGUID")) != domainGuid || SidValue(destinationDomain.Values("objectSid")) != domainSid)
            throw new InvalidOperationException("The endpoints did not prove the same domain GUID and SID.");
        // Starting at the verified NC with the critical domain-scope control is
        // the membership proof. A base search or textual DN suffix is not proof:
        // a subordinate application NC can have the same suffix.
        var original = Member(sourceSession!, sourceNc, DnFilter(capture.Dn));
        var objectGuid = GuidValue(original.Values("objectGUID"));
        var objectSid = SidValue(original.Values("objectSid"));
        if (objectGuid != capture.Guid || objectSid != capture.Sid)
            throw new InvalidOperationException("Fresh source identity does not match the retained entry identity.");
        if (new SecurityIdentifier(objectSid).AccountDomainSid?.Value != domainSid)
            throw new InvalidOperationException("The source object's account domain does not match the verified domain.");
        var replica = Member(destinationSession!, destinationNc, GuidFilter(objectGuid));
        if (GuidValue(replica.Values("objectGUID")) != objectGuid || SidValue(replica.Values("objectSid")) != objectSid)
            throw new InvalidOperationException("The destination replica did not prove the same object GUID and SID.");
        var container = Member(destinationSession!, destinationNc, DnFilter(containerDn));
        var plan = new CrossContextSavePlan(domainGuid, domainSid, objectGuid, objectSid, Dn(original),
            Dn(replica), GuidValue(container.Values("objectGUID")), Dn(container),
            LdapDistinguishedName.RelativeName(Dn(replica)), pendingName);
        return Checked(() =>
        {
            if (entry.IdentityTarget != capture.Dn || GuidValue(entry.CachedIdentityValues("objectGUID")) != capture.Guid
                || SidValue(entry.CachedIdentityValues("objectSid")) != capture.Sid)
                throw new InvalidOperationException("Retained identity changed during preflight.");
            return plan;
        });
    }

    internal DirectoryResponse SendWrite(DirectoryRequest request, Action admitted)
    {
        if (destinationSession is null || !destinationSession.CanWrite)
            throw new NotSupportedException("Only an explicitly supplied controlled transport can submit private writes.");
        var remaining = Checked(() => { var budget = Budget(); admitted(); return budget; });
        return destinationSession.SendWrite(request, remaining);
    }

    internal IdentitySearchRow ReadDestination(string dn, string filter, ProtocolScope scope, params string[] attributes)
        => Read(destinationSession ?? throw new InvalidOperationException("Destination session is missing."), dn, filter, scope, attributes);

    private IdentitySearchRow Read(CrossContextSaveSession session, string dn, string filter, ProtocolScope scope, params string[] attributes)
    {
        var remaining = Remaining();
        var request = new SearchRequest(dn, filter, scope, attributes)
            { SizeLimit = 2, TimeLimit = remaining, Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Never };
        if (scope == ProtocolScope.Subtree)
            request.Controls.Add(new DirectoryControl(AdIdentityLookup.DomainScopeControl, null, true, true));
        var response = session.Search(request, remaining);
        _ = Remaining();
        if (response.ResultCode != ResultCode.Success || response.References.Count != 0
            || response.Referral.Length != 0 || response.Entries.Count != 1)
            throw new InvalidOperationException("Cross-context reads require a complete, unreferred, unique successful response.");
        var row = response.Entries[0];
        var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in row.Attributes.AttributeNames)
            values[name] = row.Attributes[name].GetValues(name.Equals("objectGUID", StringComparison.OrdinalIgnoreCase)
                || name.Equals("objectSid", StringComparison.OrdinalIgnoreCase) ? typeof(byte[]) : typeof(string));
        return new(values, row.DistinguishedName);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try { destinationSession?.Dispose(); }
        finally { sourceSession?.Dispose(); }
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
