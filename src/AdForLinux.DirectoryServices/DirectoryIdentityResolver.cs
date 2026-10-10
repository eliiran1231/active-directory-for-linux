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
    private readonly IdentityResolverBinding binding;
    private readonly long generation;

    private DirectoryIdentityResolver(IdentityResolverBinding binding)
    {
        this.binding = binding;
        generation = binding.Capture();
    }

    internal static DirectoryIdentityResolver ForBinding(IdentityResolverBinding binding) => new(binding);

    /// <summary>Captures a revocable binding without connecting or performing a lookup.</summary>
    public static DirectoryIdentityResolver ForEntry(DirectoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return new(new EntryIdentityResolverBinding(entry));
    }

    /// <summary>Explicitly attaches this resolver to this wrapper only, without copying descriptor data.</summary>
    internal void Bind(PortableObjectSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        Checked(() => { security.BindIdentityResolver(this); return true; });
    }

    /// <summary>Translates one identity. Name-to-SID requires explicit authenticated credentials.</summary>
    /// <remarks>Same-kind conversion is offline and remains available after owner revocation.
    /// Cross-kind lookup borrows the current owner session and returns only an identity value.
    /// An unmapped identity throws IdentityNotMappedException; transport failures propagate.</remarks>
    public IdentityReference Translate(IdentityReference identity, Type targetType)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(targetType);
        if (!identity.IsValidTargetType(targetType)) throw new ArgumentException("Unsupported identity target type.", nameof(targetType));
        return Resolve([identity], targetType, targetType == typeof(SecurityIdentifier), true)[0];
    }

    /// <summary>Translates a snapshot of a collection, preserving order and unmapped values when requested.</summary>
    /// <remarks>With forceSuccess=false, unmapped inputs remain in their original positions.
    /// With forceSuccess=true, IdentityNotMappedException contains the unmapped inputs.
    /// Transport and lifetime failures are never converted into partial results.</remarks>
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

    internal T Checked<T>(Func<T> action) => binding.Checked(generation, action);
    internal IdentityReadOrigin GetReadOrigin() => binding.GetReadOrigin(generation);

    internal IdentityReference[] Resolve(IdentityReference[] identities, Type targetType, bool mutation, bool forceSuccess = true)
    {
        // Same-kind values have no authority dependency and need no session.
        if (identities.All(i => i.GetType() == targetType)) return (IdentityReference[])identities.Clone();
        foreach (var account in identities.OfType<NTAccount>())
            _ = AdIdentityLookup.EscapeText(account.Value); // reject malformed UTF-16 before opening a session
        using var operation = binding.Acquire(generation);
        var options = operation.Options; var target = operation.Target;
        if (options.Port is 3268 or 3269)
            throw new NotSupportedException("Global Catalog identity lookup requires explicit domain routing and is not supported.");
        if (string.IsNullOrWhiteSpace(target) && !(target is null && operation.UseVerifiedDomainRoot))
            throw new NotSupportedException("Identity lookup requires an entry within a verified domain naming context.");
        if (mutation && (options.IsAnonymous || options.AuthenticationType is not (AuthType.Basic or AuthType.Negotiate)
            || string.IsNullOrEmpty(options.BindDn) || string.IsNullOrEmpty(options.BindPassword)))
            throw new NotSupportedException("Name-based mutation requires explicit authenticated credentials; ambient identity pinning is not established.");
        if (target is not null) _ = AdIdentityLookup.EscapeText(target); // reject malformed UTF-16 before session creation
        // The independent session owns its connection only for this operation. The owner
        // may close concurrently: generation checks reject results, without disposing a
        // connection while its bounded request is in flight.
        var deadline = Stopwatch.StartNew();
        using var session = operation.OpenSession(options);
        Checked(() => true);
        var lookup = new AdIdentityLookup(session, options.Timeout - deadline.Elapsed, () => Checked(() => true), target, operation.UseVerifiedDomainRoot);
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
        lookup.Complete();
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
