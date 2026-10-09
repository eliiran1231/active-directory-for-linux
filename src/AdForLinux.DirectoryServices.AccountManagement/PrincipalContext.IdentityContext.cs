using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

public partial class PrincipalContext
{
    internal IdentityContextLifetime IdentityLifetime { get; } = new();
    internal Func<LdapConnectionOptions, IIdentitySearchSession> IdentitySessionFactory { get; set; }
        = static options => LdapExceptionTranslator.Execute(() => new LdapIdentitySearchSession(options));

    // Staged dependency only. The approved design's public helper names remain
    // illustrative; no new public API or transport/persistence behavior is enabled.
    internal DirectoryIdentityResolver CreateIdentityResolver()
        => DirectoryIdentityResolver.ForBinding(new ContextIdentityResolverBinding(this));

    private sealed class ContextIdentityResolverBinding(PrincipalContext context) : IdentityResolverBinding
    {
        private readonly WeakReference<PrincipalContext> owner = new(context);
        private PrincipalContext Owner() => owner.TryGetTarget(out var value) ? value
            : throw new ObjectDisposedException(nameof(PrincipalContext));
        internal override long Capture()
        {
            var context = Owner(); return context.IdentityLifetime.Capture(context.CheckDisposed);
        }
        internal override T Checked<T>(long generation, Func<T> action)
        {
            var context = Owner(); return context.IdentityLifetime.Checked(generation, context.CheckDisposed, action);
        }
        internal override IdentityResolutionOperation Acquire(long generation)
        {
            var context = Owner();
            return context.IdentityLifetime.Checked(generation, context.CheckDisposed,
                () => new IdentityResolutionOperation(context, context.BuildOptions(), context._container,
                    context._container is null, context.IdentitySessionFactory));
        }
        // Context membership does not establish an entry-specific read/write origin.
    }
}
