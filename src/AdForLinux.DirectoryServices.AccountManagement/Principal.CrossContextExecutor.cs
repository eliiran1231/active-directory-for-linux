using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.AccountManagement;

// Deliberately no live/default implementation. Only internal controlled transports
// can drive this executor until the exact wire forms and lifecycle are reviewed.
internal interface ICrossContextExecutorTransport : IDisposable
{
    DirectoryResponse Send(DirectoryRequest request);
}

public abstract partial class Principal
{
    private readonly object _crossContextGate = new();
    private volatile object? _crossContextOperation;

    internal CrossContextExecutor CreatePrivateCrossContextExecutor(PrincipalContext destination,
        Func<LdapConnectionOptions, ICrossContextExecutorTransport> openDestination)
        => new(this, destination, openDestination);

    internal sealed class CrossContextExecutor : IDisposable
    {
        internal enum Phase { Prepared, Rejected, MoveAcknowledged, ModifyAcknowledged, Uncertain, Verified, Published, Abandoned }
        internal Phase State { get; private set; } = Phase.Prepared;
        private readonly Principal principal;
        private readonly PrincipalContext source, destination;
        private readonly DirectoryEntry entry;
        private readonly object token = new();
        private readonly Dictionary<string, string> frozen;
        private readonly CrossContextSavePlan plan;
        private readonly DirectoryEntry.CrossContextLease lease;
        private readonly LdapConnectionOptions destinationOptions;
        private readonly long sourceGeneration, destinationGeneration;
        private readonly string expectedDn, newRdn;
        private ICrossContextExecutorTransport? transport;
        private bool moveAcknowledged, submitted, scalarSubmitted, disposed;

        internal CrossContextExecutor(Principal principal, PrincipalContext destination,
            Func<LdapConnectionOptions, ICrossContextExecutorTransport> openDestination)
        {
            this.principal = principal; this.destination = destination;
            lock (principal._crossContextGate)
            {
                principal.CheckDisposedOrDeleted();
                if (principal.GetType() != typeof(UserPrincipal)
                    || ((UserPrincipal)principal).HasDeferredCrossContextEdits
                    || principal._extensionCache.Values.Any(v => v.Changed))
                    throw new NotSupportedException("Private executor currently supports plain UserPrincipal scalar intent only.");
                string[] allowed = ["cn", "description", "displayName", "sAMAccountName", "userPrincipalName", "givenName", "sn", "initials"];
                if (principal._pending.Any(p => !allowed.Contains(p.Key, StringComparer.OrdinalIgnoreCase)
                    || p.Value is not string { Length: > 0 }))
                    throw new NotSupportedException("Private executor refuses non-string, deletion, extension and specialized intent.");
                frozen = principal._pending.ToDictionary(p => p.Key, p => (string)p.Value!, StringComparer.OrdinalIgnoreCase);
                source = principal.ContextRef; entry = principal.Entry ?? throw new InvalidOperationException("A persisted entry is required.");
                principal._crossContextOperation = token;
            }
            DirectoryEntry.CrossContextLease? acquired = null;
            try
            {
                sourceGeneration = source.IdentityLifetime.Capture(source.CheckDisposed);
                destinationGeneration = destination.IdentityLifetime.Capture(destination.CheckDisposed);
                plan = CrossContextSavePlan.Prepare(source, destination, entry, principal._storedGuid,
                    destination.GetCreationContainer(principal.GetType()), frozen.GetValueOrDefault("cn"));
                destinationOptions = destination.BuildOptions();
                newRdn = plan.PendingName is { } name ? "CN=" + EscapeRdnValue(name) : plan.CurrentRdn;
                expectedDn = newRdn + "," + plan.ContainerDn;
                acquired = lease = entry.ReserveCrossContext(plan.ObjectGuid, plan.ObjectSid);
                Validate();
                transport = openDestination(destinationOptions.Clone());
                Validate();
            }
            catch
            {
                // Cleanup must not prevent release of a provably unsent reservation.
                try { transport?.Dispose(); }
                finally
                {
                    if (acquired is not null) entry.ReleaseCrossContext(acquired);
                    lock (principal._crossContextGate) principal._crossContextOperation = null;
                }
                throw;
            }
        }

        private T Checked<T>(Func<T> action)
        {
            if (disposed) throw new ObjectDisposedException(nameof(CrossContextExecutor));
            T OwnerChecked() => entry.CheckedCrossContext(lease, () =>
            {
                lock (principal._crossContextGate)
                {
                    if (principal._disposed || principal._deleted || !ReferenceEquals(principal._crossContextOperation, token)
                        || !ReferenceEquals(principal.Entry, entry) || !ReferenceEquals(principal.ContextRef, source)
                        || principal._pending.Count != frozen.Count
                        || frozen.Any(p => !Equals(principal._pending.GetValueOrDefault(p.Key), p.Value))
                        || principal._extensionCache.Values.Any(v => v.Changed)
                        || ((UserPrincipal)principal).HasDeferredCrossContextEdits)
                        throw new InvalidOperationException("Frozen principal state changed.");
                    return action();
                }
            });
            T Source() => source.IdentityLifetime.Checked(sourceGeneration, source.CheckDisposed, OwnerChecked);
            T Destination() => destination.IdentityLifetime.Checked(destinationGeneration, destination.CheckDisposed, OwnerChecked);
            return source.IdentityLifetime.Id.CompareTo(destination.IdentityLifetime.Id) < 0
                ? source.IdentityLifetime.Checked(sourceGeneration, source.CheckDisposed, Destination)
                : destination.IdentityLifetime.Checked(destinationGeneration, destination.CheckDisposed, Source);
        }
        private void Validate() => Checked(() => true);
        private void Release()
        {
            Checked(() =>
            {
                entry.ReleaseCrossContext(lease); principal._crossContextOperation = null; return true;
            });
        }

        internal void Execute()
        {
            if (State != Phase.Prepared) throw new InvalidOperationException("An executor is single-submit; reconcile uncertain delivery, never retry it.");
            Validate();
            if (plan.PendingName is not null || !string.Equals(plan.ReplicaDn, expectedDn, StringComparison.OrdinalIgnoreCase))
            {
                SendWrite(new ModifyDNRequest($"<GUID={plan.ObjectGuid:D}>", $"<GUID={plan.ContainerGuid:D}>", newRdn)
                    { DeleteOldRdn = true }, Phase.MoveAcknowledged);
                moveAcknowledged = true;
            }
            Validate();
            var modify = new ModifyRequest($"<GUID={plan.ObjectGuid:D}>");
            foreach (var (name, value) in frozen.Where(p => !p.Key.Equals("cn", StringComparison.OrdinalIgnoreCase)))
            {
                var change = new DirectoryAttributeModification { Name = name, Operation = DirectoryAttributeOperation.Replace };
                change.Add(value); modify.Modifications.Add(change);
            }
            if (modify.Modifications.Count != 0)
            {
                Validate(); scalarSubmitted = true;
                SendWrite(modify, Phase.ModifyAcknowledged);
            }
            Reconcile();
        }

        private void SendWrite(DirectoryRequest request, Phase acknowledged)
        {
            Validate();
            // No source authority is available to the transport, and no compensation
            // is attempted. A known post-move rejection remains quarantined too.
            State = Phase.Uncertain; submitted = true;
            DirectoryResponse response;
            try { response = transport!.Send(request); }
            catch (DirectoryOperationException error) when (error.Response is { ResultCode: not ResultCode.Success })
            { Reject(); throw; }
            if (response.ResultCode != ResultCode.Success) { Reject(); throw new DirectoryOperationException(response); }
            if (response.Referral.Length != 0) throw new InvalidOperationException("Referred write outcome is not a verified acknowledgement.");
            State = acknowledged;
        }
        private void Reject()
        {
            State = moveAcknowledged ? Phase.MoveAcknowledged : Phase.Rejected;
            if (!moveAcknowledged) Release();
        }

        internal void Reconcile()
        {
            if (State is not (Phase.Uncertain or Phase.MoveAcknowledged or Phase.ModifyAcknowledged or Phase.Prepared or Phase.Verified))
                throw new InvalidOperationException("This operation cannot be reconciled in its current state.");
            if ((!scalarSubmitted && frozen.Keys.Any(k => !k.Equals("cn", StringComparison.OrdinalIgnoreCase)))
                || (State == Phase.Prepared && (frozen.Count != 0 || !string.Equals(plan.ReplicaDn, expectedDn, StringComparison.OrdinalIgnoreCase))))
                throw new InvalidOperationException("Readback cannot acknowledge unsent edits. Explicitly resolve the partial operation first.");
            Validate();
            var root = Read("", "(objectClass=*)", ProtocolScope.Base,
                "defaultNamingContext", "configurationNamingContext", "namingContexts", "supportedControl");
            var nc = AdIdentityDomainMetadata.ValidateRoot([root]).Domain;
            var domain = Read(nc, "(objectClass=domainDNS)", ProtocolScope.Base, "objectGUID", "objectSid");
            RequireIdentity(domain, plan.DomainGuid, plan.DomainSid);
            var row = Read(nc, "(objectGUID=" + LdapFilter.EscapeBytes(plan.ObjectGuid.ToByteArray()) + ")", ProtocolScope.Subtree,
                frozen.Keys.Where(k => !k.Equals("cn", StringComparison.OrdinalIgnoreCase))
                    .Concat(["objectGUID", "objectSid", "distinguishedName"]).ToArray());
            RequireIdentity(row, plan.ObjectGuid, plan.ObjectSid);
            if (!string.Equals(row.DistinguishedName, expectedDn, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(row.Text("distinguishedName"), expectedDn, StringComparison.OrdinalIgnoreCase)
                || frozen.Where(p => !p.Key.Equals("cn", StringComparison.OrdinalIgnoreCase)).Any(p => row.Text(p.Key) != p.Value))
                throw new InvalidOperationException("Readback does not prove the complete requested state; retain quarantine and intent.");
            var container = Read(nc, "(&(objectGUID=" + LdapFilter.EscapeBytes(plan.ContainerGuid.ToByteArray())
                + ")(distinguishedName=" + AdIdentityLookup.EscapeText(plan.ContainerDn) + "))", ProtocolScope.Subtree,
                "objectGUID", "distinguishedName");
            if (container.Values("objectGUID") is not [byte[] { Length: 16 } containerGuid]
                || new Guid(containerGuid) != plan.ContainerGuid
                || !string.Equals(container.DistinguishedName, plan.ContainerDn, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(container.Text("distinguishedName"), plan.ContainerDn, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Readback does not prove the destination container identity.");
            State = Phase.Verified;
            // Close source sessions outside all owner locks. Any cleanup failure
            // prevents publication and leaves the original wrapper quarantined.
            entry.CloseCrossContextSourceConnections(lease);
            Checked(() =>
            {
                entry.PublishCrossContext(lease, destinationOptions, expectedDn, () =>
                {
                    principal.ContextRef = destination;
                    principal._pending.Clear(); principal._initialScalars = null; principal._loadedScalars.Clear();
                    principal._crossContextOperation = null;
                });
                State = Phase.Published; return true;
            });
        }
        private IdentitySearchRow Read(string dn, string filter, ProtocolScope scope, params string[] attributes)
        {
            Validate();
            var request = new SearchRequest(dn, filter, scope, attributes)
                { SizeLimit = 2, Aliases = System.DirectoryServices.Protocols.DereferenceAlias.Never };
            if (scope == ProtocolScope.Subtree) request.Controls.Add(new DirectoryControl(AdIdentityLookup.DomainScopeControl, null, true, true));
            var response = (SearchResponse)transport!.Send(request);
            Validate();
            if (response.ResultCode != ResultCode.Success || response.Referral.Length != 0 || response.References.Count != 0 || response.Entries.Count != 1)
                throw new InvalidOperationException("Incomplete reconciliation response.");
            var row = response.Entries[0]; var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in row.Attributes.AttributeNames)
                values[name] = row.Attributes[name].GetValues(name.Equals("objectGUID", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("objectSid", StringComparison.OrdinalIgnoreCase) ? typeof(byte[]) : typeof(string));
            return new(values, row.DistinguishedName);
        }
        private static void RequireIdentity(IdentitySearchRow row, Guid guid, string sid)
        {
            if (row.Values("objectGUID") is not [byte[] { Length: 16 } bytes] || new Guid(bytes) != guid
                || row.Values("objectSid") is not [byte[] sidBytes]) throw new InvalidOperationException("Missing immutable identity.");
            var actual = new SecurityIdentifier(sidBytes, 0);
            if (actual.Value != sid || actual.BinaryLength != sidBytes.Length) throw new InvalidOperationException("Wrong immutable identity.");
        }
        public void Dispose()
        {
            if (disposed) return;
            try
            {
                if (!submitted && State == Phase.Prepared) { Release(); State = Phase.Abandoned; }
            }
            finally { disposed = true; transport?.Dispose(); transport = null; }
            // Submitted-but-unpublished operations never release quarantine on disposal.
        }
    }
}
