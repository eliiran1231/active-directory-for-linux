using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

// Internal layer boundary: the high layer can borrow its actual owner without
// creating a credential-owning DirectoryEntry clone or a reverse project reference.
internal abstract class IdentityResolverBinding
{
    internal abstract long Capture();
    internal abstract T Checked<T>(long generation, Func<T> action);
    internal abstract IdentityResolutionOperation Acquire(long generation);
    internal virtual IdentityReadOrigin GetReadOrigin(long generation)
        => throw new NotSupportedException("This identity binding does not establish a DirectoryEntry raw-write origin.");
}

// A short-lived operation, never stored on a resolver or descriptor. Keeps the
// weakly borrowed owner alive until I/O/publication checks finish, including failure.
internal sealed class IdentityResolutionOperation(
    object owner, LdapConnectionOptions options, string? target, bool useVerifiedDomainRoot,
    Func<LdapConnectionOptions, IIdentitySearchSession> openSession) : IDisposable
{
    private object? ownerLease = owner;
    internal LdapConnectionOptions Options { get; } = options;
    internal string? Target { get; } = target;
    internal bool UseVerifiedDomainRoot { get; } = useVerifiedDomainRoot;
    internal Func<LdapConnectionOptions, IIdentitySearchSession> OpenSession { get; } = openSession;
    public void Dispose() { GC.KeepAlive(ownerLease); ownerLease = null; }
}

internal sealed class EntryIdentityResolverBinding(DirectoryEntry entry) : IdentityResolverBinding
{
    private readonly WeakReference<DirectoryEntry> owner = new(entry);
    private DirectoryEntry Owner() => owner.TryGetTarget(out var value) ? value
        : throw new ObjectDisposedException(nameof(DirectoryEntry));
    internal override long Capture()
    {
        var entry = Owner(); return entry.IdentityLifetime.Capture(entry.ThrowIfDisposed);
    }
    internal override T Checked<T>(long generation, Func<T> action)
    {
        var entry = Owner(); return entry.IdentityLifetime.Checked(generation, entry.ThrowIfDisposed, action);
    }
    internal override IdentityResolutionOperation Acquire(long generation)
    {
        var entry = Owner();
        return entry.IdentityLifetime.Checked(generation, entry.ThrowIfDisposed,
            () => new IdentityResolutionOperation(entry, entry.BuildOptions(), entry.IdentityTarget, false, entry.IdentitySessionFactory));
    }
    internal override IdentityReadOrigin GetReadOrigin(long generation)
    {
        var entry = Owner();
        return entry.IdentityLifetime.Checked(generation, entry.ThrowIfDisposed,
            () => new IdentityReadOrigin(entry.IdentityLifetime.Id, generation, entry.IdentityTarget));
    }
}
