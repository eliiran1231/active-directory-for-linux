using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Persistent authenticated resource, owned by the pool, not by a checkout.
/// Owns the complete native session (including native referral children).
/// No in-place rebind or managed request replay is permitted.
/// </summary>
internal sealed class BoundLdapSession : IDisposable
{
    private readonly LdapConnection? connection;
    private readonly ILdapRequestTransport transport;
    private IDisposable? owner;
    internal LdapConnectionOptions Profile { get; }
    internal LdapAuthenticationSource Authentication { get; }
    internal ReferralChasingOption? Referrals { get; }
    internal LdapConnection? ProtocolsConnection => owner is not null ? connection : throw new ObjectDisposedException(nameof(BoundLdapSession));
    internal LdapConnection Connection => ProtocolsConnection ?? throw new PlatformNotSupportedException("This session has a neutral transport, not a Protocols handle.");
    internal ILdapRequestTransport Transport => owner is not null ? transport : throw new ObjectDisposedException(nameof(BoundLdapSession));

    internal BoundLdapSession(LdapConnection connection, LdapConnectionOptions profile,
        LdapAuthenticationSource authentication, ReferralChasingOption? referrals)
    {
        this.connection = connection; owner = connection; transport = new ProtocolsLdapTransport(connection);
        Profile = profile.Clone();
        Authentication = authentication;
        Referrals = referrals;
    }

    internal BoundLdapSession(ILdapRequestTransport transport, IDisposable owner, LdapConnectionOptions profile,
        LdapAuthenticationSource authentication, ReferralChasingOption? referrals)
    {
        this.transport = transport; this.owner = owner;
        Profile = profile.Clone(); Authentication = authentication; Referrals = referrals;
    }

    public void Dispose() => Interlocked.Exchange(ref owner, null)?.Dispose();
}
