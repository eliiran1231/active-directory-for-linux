using AdForLinux.DirectoryServices.Ldap;
using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    private volatile object? _crossContextReservation;
    private bool _crossContextCleanupFailed;
    private long _crossContextAuthorityEpoch;
    private Action CapturePropertyOwnerValidation()
    {
        var epoch = Interlocked.Read(ref _crossContextAuthorityEpoch);
        return () =>
        {
            if (Interlocked.Read(ref _crossContextAuthorityEpoch) != epoch)
                throw new InvalidOperationException("This property wrapper belongs to a revoked binding.");
            ThrowIfDisposed();
        };
    }
    private void CheckCrossContextReservation()
    {
        if (_crossContextReservation is not null)
            throw new InvalidOperationException("This entry is reserved or quarantined by a cross-context operation; reconcile that operation before reuse.");
    }

    // Operation-owned lease, never part of the data-only preflight plan.
    internal sealed record CrossContextLease(object Token, long Generation, long Version,
        PropertyCollection? Cache, PropertyValueCollection[] Ledgers, long[] Versions, object?[][] Values);

    internal CrossContextLease ReserveCrossContext(Guid expectedGuid, string expectedSid)
    {
        var generation = IdentityLifetime.Capture(ThrowIfDisposed);
        return IdentityLifetime.Checked(generation, ThrowIfDisposed, () =>
        {
            lock (_entryWriteGate)
            {
                if (CachedIdentityValues("objectGUID") is not [byte[] guid] || new Guid(guid) != expectedGuid
                    || CachedIdentityValues("objectSid") is not [byte[] sid]
                    || new AdForLinux.Security.Principal.SecurityIdentifier(sid, 0).Value != expectedSid)
                    throw new InvalidOperationException("Retained immutable identity changed after preflight.");
                var ledgers = _properties?.CachedLedgers ?? [];
                if (_isNew || _uncertainWrite is not null || _commitRunning != 0 || _objectSecurity is not null
                    || _pendingPropertyChanges.Count != 0 || ledgers.Any(p => p.Changed))
                    throw new NotSupportedException("The private cross-context executor requires a clean entry with no raw/security or uncertain intent.");
                var versions = ledgers.Select(p => p.ChangeVersion).ToArray();
                foreach (var property in ledgers) property.ReserveCrossContext();
                _crossContextReservation = new object();
                IdentityLifetime.Invalidate(); // revoke source resolvers before any private send
                return new CrossContextLease(_crossContextReservation,
                    IdentityLifetime.Capture(ThrowIfActuallyDisposed), _entryChangeVersion, _properties, ledgers, versions,
                    ledgers.Select(p => p.Select(v => v is byte[] b ? (object)b.Clone() : v).ToArray()).ToArray());
            }
        });
    }

    private sealed class CrossContextValueComparer : IEqualityComparer<object?>
    {
        internal static readonly CrossContextValueComparer Instance = new();
        public new bool Equals(object? left, object? right) => left is byte[] a && right is byte[] b
            ? a.SequenceEqual(b) : object.Equals(left, right);
        public int GetHashCode(object? value) => 0;
    }

    internal T CheckedCrossContext<T>(CrossContextLease lease, Func<T> action)
        => IdentityLifetime.Checked(lease.Generation, ThrowIfActuallyDisposed, () =>
        {
            lock (_entryWriteGate)
            {
                var acquired = 0;
                try
                {
                    foreach (var property in lease.Ledgers) { Monitor.Enter(property.ChangeGate); acquired++; }
                    if (!ReferenceEquals(_crossContextReservation, lease.Token) || _entryChangeVersion != lease.Version
                        || !ReferenceEquals(_properties, lease.Cache) || _pendingPropertyChanges.Count != 0
                        || lease.Ledgers.Where((p, i) => p.ChangeVersion != lease.Versions[i]
                            || !p.SequenceEqual(lease.Values[i], CrossContextValueComparer.Instance)).Any())
                        throw new InvalidOperationException("The reserved entry state changed.");
                    return action();
                }
                finally { for (var i = acquired - 1; i >= 0; i--) Monitor.Exit(lease.Ledgers[i].ChangeGate); }
            }
        });

    internal void ReleaseCrossContext(CrossContextLease lease)
        => CheckedCrossContext(lease, () =>
        {
            foreach (var property in lease.Ledgers) property.ReleaseCrossContext();
            _crossContextReservation = null; return true;
        });

    internal void CloseCrossContextSourceConnections(CrossContextLease lease)
    {
        var connections = CheckedCrossContext(lease, () =>
        {
            if (_crossContextCleanupFailed) throw new InvalidOperationException("Source cleanup failed; publication remains quarantined.");
            var result = new[] { _connection, _schemaConnection }.Where(c => c is not null).Distinct().ToArray();
            _connection = null; _schemaConnection = null; return result;
        });
        List<Exception> failures = [];
        foreach (var connection in connections)
            try { connection!.Dispose(); } catch (Exception error) { failures.Add(error); }
        if (failures.Count != 0)
        {
            lock (_entryWriteGate) _crossContextCleanupFailed = true;
            throw new AggregateException("Source connection cleanup failed; entry remains quarantined.", failures);
        }
    }

    internal void PublishCrossContext(CrossContextLease lease, LdapConnectionOptions destination, string dn, Action publishPrincipal)
    {
        var path = new LdapPath(destination.Host, destination.Port, dn);
        var options = destination.Clone();
        var authentication = options.AuthenticationType switch
        {
            AuthType.Negotiate => AuthenticationTypes.Secure,
            AuthType.Anonymous => AuthenticationTypes.Anonymous,
            _ => AuthenticationTypes.None
        };
        if (options.UseSsl) authentication |= AuthenticationTypes.SecureSocketsLayer;
        if (options.Signing) authentication |= AuthenticationTypes.Signing;
        if (options.Sealing) authentication |= AuthenticationTypes.Sealing;
        CheckedCrossContext(lease, () =>
        {
            // Everything fallible is prepared first. No network or external callback
            // runs here; publishPrincipal is the high layer's local field publication.
            Interlocked.Increment(ref _crossContextAuthorityEpoch);
            _properties?.Revoke(); _options?.Revoke();
            _properties = null; _options = null; _objectSecurity = null;
            _path = path; _pathText = path.ToString(); _boundDistinguishedName = null;
            _username = options.BindDn; _password = options.BindPassword;
            _authenticationType = authentication; _connectionOptionsOverride = options;
            SchemaFilterNames = []; _entryChangeVersion++;
            IdentityLifetime.Invalidate();
            publishPrincipal();
            _crossContextReservation = null;
            return true;
        });
    }
}
