using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

public abstract partial class ObjectSecurity
{
    private DirectoryIdentityResolver? identityResolver;
    private long identityAttachment;
    private readonly ThreadLocal<Stack<ResolvedMutation>> preparedIdentities = new(() => new());
    private readonly ThreadLocal<int> libraryWriteDepth = new();
    internal void EnterLibraryWriteLock() { WriteLock(); libraryWriteDepth.Value++; }
    internal void ExitLibraryWriteLock() { libraryWriteDepth.Value--; WriteUnlock(); }

    internal void BindIdentityResolver(DirectoryIdentityResolver resolver)
    {
        lock (FacadeMutation.Gate) { identityResolver = resolver; identityAttachment++; }
    }

    internal void RequireRetrievedSection(SecurityMasks sections)
    {
        if (HasRawReadContext && (sections & ~RetrievedSections) != 0)
            throw new InvalidOperationException("The requested security section was not retrieved.");
    }

    internal sealed record IdentityRead(DirectoryIdentityResolver? Resolver, long Attachment, long Version);
    internal IdentityRead CaptureIdentityRead()
    {
        lock (FacadeMutation.Gate) return new(identityResolver, identityAttachment, _securityDescriptor.MutationVersion);
    }
    internal T ValidateIdentityRead<T>(IdentityRead read, Func<T> publish)
    {
        T Check()
        {
            lock (FacadeMutation.Gate)
            {
                if (identityAttachment != read.Attachment || !ReferenceEquals(identityResolver, read.Resolver)
                    || _securityDescriptor.MutationVersion != read.Version)
                    throw new InvalidOperationException("The descriptor or its identity context changed during resolution.");
                return publish();
            }
        }
        return read.Resolver is null ? Check() : read.Resolver.Checked(Check);
    }
    internal void RequireUnlockedResolution()
    {
        if (_lock.IsReadLockHeld || _lock.IsWriteLockHeld || Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("Identity lookup cannot execute while a security lock is held.");
    }
    internal IdentityReference[] ResolveRead(IdentityRead read, IdentityReference[] identities, Type targetType)
    {
        foreach (var identity in identities)
            if (!identity.IsValidTargetType(targetType)) identity.Translate(targetType); // native validation contract
        RequireUnlockedResolution();
        if (read.Resolver is null)
        {
            // Retain the detached same-kind/explicit-missing-context contract.
            return identities.Select(identity => identity.Translate(targetType)).ToArray();
        }
        var result = read.Resolver.Resolve(identities, targetType, false);
        return ValidateIdentityRead(read, () => result);
    }

    internal ResolvedMutation PrepareIdentityMutation(IdentityReference identity)
    {
        var stack = preparedIdentities.Value!;
        if (stack.TryPeek(out var existing) && existing.Identity.Equals(identity)) return new(this, existing);
        if (identity is SecurityIdentifier sid) return new(this, identity, sid, null);
        // Public modify hooks retain their native lock/dispatch behavior. Only the
        // concrete base implementation resolves, so an override that declines the
        // operation performs no lookup. Suspend only locks acquired by this library;
        // never release a caller's protected lock or a shared transaction gate.
        var depth = libraryWriteDepth.Value;
        if (_lock.IsReadLockHeld || _lock.RecursiveWriteCount != depth || Monitor.IsEntered(FacadeMutation.Gate))
            throw new InvalidOperationException("Identity lookup cannot execute while a caller security lock is held.");
        var read = CaptureIdentityRead();
        SecurityIdentifier resolved;
        for (var i = 0; i < depth; i++) WriteUnlock();
        try
        {
            resolved = read.Resolver is null ? (SecurityIdentifier)identity.Translate(typeof(SecurityIdentifier))
                : (SecurityIdentifier)read.Resolver.Resolve([identity], typeof(SecurityIdentifier), true)[0];
        }
        finally { for (var i = 0; i < depth; i++) WriteLock(); }
        ValidateIdentityRead(read, () => true);
        return new(this, identity, resolved, read);
    }

    // Wrapper-local, thread-scoped prepared values preserve virtual hook arguments
    // while ensuring their base implementation never performs LDAP under its locks.
    // This is not an ambient resolver and never attaches authority to an identity value.
    internal sealed class ResolvedMutation : IDisposable
    {
        private readonly ObjectSecurity owner;
        private readonly ResolvedMutation? parent;
        private IdentityRead? read;
        internal IdentityReference Identity { get; }
        internal SecurityIdentifier Sid { get; }
        internal ResolvedMutation(ObjectSecurity owner, IdentityReference identity, SecurityIdentifier sid, IdentityRead? read)
        { this.owner = owner; Identity = identity; Sid = sid; this.read = read; owner.preparedIdentities.Value!.Push(this); }
        internal ResolvedMutation(ObjectSecurity owner, ResolvedMutation parent)
        { this.owner = owner; this.parent = parent; Identity = parent.Identity; Sid = parent.Sid; owner.preparedIdentities.Value!.Push(this); }
        internal T Run<T>(Func<T> action)
        {
            if (parent is not null) return parent.Run(action);
            T Publish()
            {
                var result = FacadeMutation.Run(action);
                if (read is not null) read = read with { Version = owner._securityDescriptor.MutationVersion };
                return result;
            }
            return read is null ? FacadeMutation.Run(action) : owner.ValidateIdentityRead(read, Publish);
        }
        internal void Run(Action action) => Run(() => { action(); return true; });
        public void Dispose()
        {
            if (!ReferenceEquals(owner.preparedIdentities.Value!.Pop(), this)) throw new InvalidOperationException("Identity preparation scopes must be nested.");
        }
    }
}
