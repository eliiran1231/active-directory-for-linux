using System.DirectoryServices.Protocols;
using System.Runtime.ExceptionServices;

namespace AdForLinux.DirectoryServices.Ldap;

// One admitted, same-target operation; not an ambient session-reuse authority.
// Generic provider selection remains disabled; admitted restricted workers use this owner.
// Cross-target pairs need distinct owners.
internal sealed class NativeLdapOperation : IDisposable
{
    private readonly LdapConnectionOptions recipe;
    private readonly LdapAuthenticationSource provenance;
    private readonly Lazy<NativeLdapBindingBackend.Authority> authority;
    private readonly CancellationToken cancellationToken;
    private LdapConnectionProvider.Session[] sessions = [];
    private int disposed, remainingSessions, authorityClosed;
    internal IReadOnlyList<LdapConnectionProvider.Session> Sessions => sessions;

    private NativeLdapOperation(LdapConnectionOptions options, ReferralChasingOption referrals,
        NativeLdapBindingBackend.IBindingApi? api, CancellationToken cancellationToken, LdapCredentialSource? source)
    {
        if (!NativeLdapBindingBackend.CanRepresentBinding(options, referrals))
            throw new PlatformNotSupportedException("The native operation cannot represent the complete binding profile.");
        source?.Validate();
        var sourceRecipe = source is null ? null : source with { };
        if (sourceRecipe is not null && api is not null && api is not NativeLdapBindingBackend.ISourceBindingApi)
            throw new PlatformNotSupportedException("The binding API cannot consume an explicit credential source.");
        recipe = options.Clone(); provenance = new(recipe); this.cancellationToken = cancellationToken;
        // Capture point: after atomic pool admission, immediately before first bind.
        // Impossible/queued admission does not acquire any credential resources.
        authority = new(() => api is null
            ? NativeLdapBindingBackend.ResolveForBinding(recipe, referrals, cancellationToken, sourceRecipe)
            : NativeLdapBindingBackend.ResolveForBinding(recipe, referrals, api, cancellationToken, sourceRecipe));
    }
    internal static NativeLdapOperation Acquire(
        BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession> pool,
        LdapConnectionOptions options, int count, ReferralChasingOption referrals = ReferralChasingOption.None,
        CancellationToken cancellationToken = default, NativeLdapBindingBackend.IBindingApi? api = null, LdapCredentialSource? source = null)
    {
        if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
        cancellationToken.ThrowIfCancellationRequested();
        var owner = new NativeLdapOperation(options, referrals, api, cancellationToken, source);
        BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>.Lease[]? leases = null;
        try
        {
            leases = pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(owner.recipe, referrals),
                count, owner.BindResource, cancellationToken, reusable: false);
            // Publication is all-or-nothing. On construction failure none of these
            // wrappers escape; the catch disposes every raw lease before the owner.
            owner.remainingSessions = leases.Length;
            owner.sessions = leases.Select(lease => new LdapConnectionProvider.Session(lease, owner.ReleaseMember)).ToArray();
            return owner;
        }
        catch
        {
            if (leases is not null) foreach (var lease in leases) { lease.Invalidate(); lease.Dispose(); }
            owner.CloseAuthority(); throw;
        }
    }
    private BoundLdapSession BindResource()
    {
        ObjectDisposedException.ThrowIf(disposed != 0, this);
        var native = authority.Value.Bind(cancellationToken);
        try { return new BoundLdapSession(native, native, recipe, provenance, ReferralChasingOption.None); }
        catch { native.Dispose(); throw; }
    }
    private void ReleaseMember()
    {
        if (Interlocked.Decrement(ref remainingSessions) == 0) CloseAuthority();
    }
    private void CloseAuthority()
    {
        if (Interlocked.Exchange(ref authorityClosed, 1) == 0 && authority.IsValueCreated) authority.Value.Dispose();
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        Exception? failure = null;
        foreach (var session in sessions)
            try { session.Dispose(); } catch (Exception error) { failure ??= error; }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
