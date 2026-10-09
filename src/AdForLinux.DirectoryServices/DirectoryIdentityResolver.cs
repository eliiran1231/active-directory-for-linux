using System.DirectoryServices.Protocols;
using System.Diagnostics;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.Security.Principal;
using PortableObjectSecurity = AdForLinux.Security.AccessControl.ObjectSecurity;

namespace AdForLinux.DirectoryServices;

/// <summary>Resolves portable identities in an entry's domain using its current, borrowed binding.</summary>
/// <remarks>Keep the entry alive. Rebinding, closing, refreshing its descriptor or disposing
/// the entry invalidates this resolver. Reacquire explicitly; no credentials are retained here.</remarks>
public sealed class DirectoryIdentityResolver
{
    private readonly WeakReference<DirectoryEntry> entry;
    private readonly long generation;

    private DirectoryIdentityResolver(DirectoryEntry owner)
    {
        entry = new(owner);
        generation = owner.IdentityLifetime.Capture(owner.ThrowIfDisposed);
    }

    /// <summary>Captures a revocable binding without connecting or performing a lookup.</summary>
    public static DirectoryIdentityResolver ForEntry(DirectoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return new(entry);
    }

    /// <summary>Explicitly attaches this resolver to this wrapper only, without copying descriptor data.</summary>
    public void Bind(PortableObjectSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        Checked(() => { security.BindIdentityResolver(this); return true; });
    }

    /// <summary>Translates one identity. Name-to-SID requires explicit authenticated credentials.</summary>
    public IdentityReference Translate(IdentityReference identity, Type targetType)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(targetType);
        if (!identity.IsValidTargetType(targetType)) throw new ArgumentException("Unsupported identity target type.", nameof(targetType));
        return Resolve([identity], targetType, targetType == typeof(SecurityIdentifier), true)[0];
    }

    /// <summary>Translates a snapshot of a collection, preserving order and unmapped values when requested.</summary>
    public IdentityReferenceCollection Translate(IdentityReferenceCollection identities, Type targetType, bool forceSuccess = false)
    {
        ArgumentNullException.ThrowIfNull(identities);
        ArgumentNullException.ThrowIfNull(targetType);
        if (targetType != typeof(SecurityIdentifier) && targetType != typeof(NTAccount))
            throw new ArgumentException("Unsupported identity target type.", nameof(targetType));
        var result = new IdentityReferenceCollection(identities.Count);
        foreach (var value in Resolve(identities.ToArray(), targetType, targetType == typeof(SecurityIdentifier), forceSuccess)) result.Add(value);
        return result;
    }

    internal T Checked<T>(Func<T> action)
    {
        if (!entry.TryGetTarget(out var owner)) throw new ObjectDisposedException(nameof(DirectoryEntry), "The identity context owner is no longer available.");
        return owner.IdentityLifetime.Checked(generation, owner.ThrowIfDisposed, action);
    }
    internal IdentityReadOrigin GetReadOrigin()
    {
        if (!entry.TryGetTarget(out var owner)) throw new ObjectDisposedException(nameof(DirectoryEntry));
        return Checked(() => new IdentityReadOrigin(owner.IdentityLifetime.Id, generation, owner.IdentityTarget));
    }

    internal IdentityReference[] Resolve(IdentityReference[] identities, Type targetType, bool mutation, bool forceSuccess = true)
    {
        // Same-kind values have no authority dependency and need no session.
        if (identities.All(i => i.GetType() == targetType)) return (IdentityReference[])identities.Clone();
        foreach (var account in identities.OfType<NTAccount>())
            _ = AdIdentityLookup.EscapeText(account.Value); // reject malformed UTF-16 before opening a session
        if (!entry.TryGetTarget(out var owner)) throw new ObjectDisposedException(nameof(DirectoryEntry));
        var (options, target) = Checked(() => (owner.BuildOptions(), owner.IdentityTarget));
        if (options.Port is 3268 or 3269)
            throw new NotSupportedException("Global Catalog identity lookup requires explicit domain routing and is not supported.");
        if (string.IsNullOrWhiteSpace(target))
            throw new NotSupportedException("Identity lookup requires an entry within a verified domain naming context.");
        if (mutation && (options.IsAnonymous || options.AuthenticationType is not (AuthType.Basic or AuthType.Negotiate)
            || string.IsNullOrEmpty(options.BindDn) || string.IsNullOrEmpty(options.BindPassword)))
            throw new NotSupportedException("Name-based mutation requires explicit authenticated credentials; ambient identity pinning is not established.");
        // The independent session owns its connection only for this operation. The entry
        // may close concurrently: generation checks reject results, without disposing a
        // connection while its bounded request is in flight.
        var deadline = Stopwatch.StartNew();
        using var session = owner.IdentitySessionFactory(options);
        Checked(() => true);
        var lookup = new AdIdentityLookup(session, options.Timeout - deadline.Elapsed, () => Checked(() => true), target);
        var cache = new Dictionary<IdentityReference, IdentityReference?>();
        var result = new IdentityReference[identities.Length];
        var missing = new IdentityNotMappedException();
        for (var i = 0; i < identities.Length; i++)
        {
            var identity = identities[i];
            if (identity.GetType() == targetType) { result[i] = identity; continue; }
            if (!cache.TryGetValue(identity, out var translated)) cache.Add(identity, translated = lookup.Translate(identity));
            result[i] = translated ?? identity;
            if (translated is null) missing.UnmappedIdentities.Add(identity);
        }
        Checked(() => true);
        if (forceSuccess && missing.UnmappedIdentities.Count != 0) throw missing;
        return result;
    }
}

// Only short local state/capture/publication operations execute under this gate.
// Connection creation, LDAP and externally supplied callbacks never do.
internal sealed class IdentityContextLifetime
{
    internal Guid Id { get; } = Guid.NewGuid();
    private readonly object gate = new();
    private long generation;
    private int changing;
    internal long Capture(Action validate)
    { lock (gate) { validate(); if (changing != 0) throw Stale(); return generation; } }
    internal T Checked<T>(long expected, Action validate, Func<T> action)
    { lock (gate) { validate(); if (changing != 0 || generation != expected) throw Stale(); return action(); } }
    internal IDisposable Change()
    { lock (gate) { generation++; changing++; return new ChangeScope(this); } }
    internal void Invalidate() { lock (gate) generation++; }
    private static InvalidOperationException Stale() => new("The identity context is stale. Explicitly reacquire it from the current entry.");
    private sealed class ChangeScope(IdentityContextLifetime owner) : IDisposable
    { public void Dispose() { lock (owner.gate) owner.changing--; } }
}

// Non-secret read provenance only: no owner reference, resolver or credential capability.
internal sealed record IdentityReadOrigin(Guid Owner, long Generation, string DistinguishedName);
