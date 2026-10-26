using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

internal enum LdapSessionFreshness
{
    CompatibleEstablishedSession,
    FreshBind,
}

[Flags]
internal enum LdapAuthenticationCapabilities
{
    None = 0,
    // A complete explicit recipe is consumed by every replacement bind.
    RepeatableBindAuthority = 1,
    // Native referral children preserve the backend's existing policy.
    StableReferralPolicy = 2,
}

internal enum LdapAuthenticationProvenance
{
    Anonymous,
    ExplicitBasic,
    ExplicitPlatform,
    AmbientPlatform,
}

/// <summary>
/// Immutable bind recipe and provenance owner. This is not a captured Kerberos
/// identity: the Protocols backend cannot resolve and consume a target-specific
/// ambient authority. Such sources must bind afresh at operation acquisition.
/// </summary>
internal sealed class LdapAuthenticationSource
{
    private readonly LdapConnectionOptions recipe;
    internal LdapAuthenticationProvenance Provenance { get; }
    internal bool RequiresOperationLease => Provenance is
        LdapAuthenticationProvenance.AmbientPlatform or LdapAuthenticationProvenance.ExplicitPlatform;

    internal LdapAuthenticationSource(LdapConnectionOptions options)
    {
        recipe = options.Clone();
        Provenance = recipe.IsAnonymous ? LdapAuthenticationProvenance.Anonymous
            : recipe.AuthenticationType == AuthType.Basic ? LdapAuthenticationProvenance.ExplicitBasic
            : string.IsNullOrEmpty(recipe.BindDn) ? LdapAuthenticationProvenance.AmbientPlatform
            : LdapAuthenticationProvenance.ExplicitPlatform;
    }

    // Resolution and binding are deliberately one owner. A future backend must
    // supply a target-aware, binder-consumed authority here, not a caller-provided
    // principal/cache-path label that independently grants pool eligibility.
    internal LdapAuthenticationCapabilities Capabilities(ReferralChasingOption referrals)
    {
        if (recipe.RestrictedKerberos is not null || Provenance != LdapAuthenticationProvenance.ExplicitBasic || string.IsNullOrEmpty(recipe.BindPassword))
            return LdapAuthenticationCapabilities.None;
        // Preserve PR235's Linux Basic policy (including anonymous referral
        // children). Windows native children require the separate scoped check.
        return LdapAuthenticationCapabilities.RepeatableBindAuthority |
            (referrals == ReferralChasingOption.None || OperatingSystem.IsLinux()
                ? LdapAuthenticationCapabilities.StableReferralPolicy : LdapAuthenticationCapabilities.None);
    }

    internal LdapSessionFreshness Freshness(ReferralChasingOption referrals)
        => Capabilities(referrals) == (LdapAuthenticationCapabilities.RepeatableBindAuthority |
            LdapAuthenticationCapabilities.StableReferralPolicy)
            ? LdapSessionFreshness.CompatibleEstablishedSession : LdapSessionFreshness.FreshBind;

    internal BoundLdapSession Bind(ReferralChasingOption? referrals, TimeSpan? bindTimeout = null)
    {
        var profile = recipe.Clone();
        var connection = LdapConnectionFactory.Create(profile.Clone(bindTimeout));
        LdapConnectionFactory.ConfigureOwned(connection, value =>
        {
            // Null is reserved for credential validation, which preserves the
            // platform default referral policy and never returns to the pool.
            if (referrals is { } requested)
                LdapConnectionFactory.ConfigureReferralChasing(value, requested);
            value.Bind();
            value.Timeout = profile.Timeout;
        });
        return new BoundLdapSession(connection, profile, this, referrals);
    }
}
