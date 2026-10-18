namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    // Unlike IdentityLifetime generations, this epoch changes only when the
    // private cross-context executor publishes a different authority. Close and
    // refresh do not revoke retained provider wrappers.
    internal sealed class BindingAuthority(DirectoryEntry owner, long epoch)
    {
        private void Check()
        {
            if (Interlocked.Read(ref owner._crossContextAuthorityEpoch) != epoch)
                throw new InvalidOperationException("This handle belongs to a revoked entry authority.");
            owner.CheckCrossContextReservation();
        }

        internal T Checked<T>(Func<T> action)
        {
            var generation = owner.IdentityLifetime.Capture(Check);
            return owner.IdentityLifetime.Checked(generation, Check, () =>
            {
                lock (owner._entryWriteGate) return action();
            });
        }
        internal void Validate() => Checked(() => true);
    }

    internal BindingAuthority CaptureBindingAuthority()
        => new(this, Interlocked.Read(ref _crossContextAuthorityEpoch));

    internal DirectoryEntry CopyBinding(BindingAuthority authority, string? dn = null)
        => authority.Checked(() =>
        {
            var path = new Ldap.LdapPath(_path.Host, _path.Port, dn ?? _path.DistinguishedName).ToString();
            return CopyConnectionFreshnessTo(_connectionOptionsOverride is null
                ? new DirectoryEntry(path, _username, _password, _authenticationType)
                : new DirectoryEntry(path, _connectionOptionsOverride.Clone()));
        });

    internal System.DirectoryServices.Protocols.LdapConnection GetAuthorityConnection(BindingAuthority authority, bool schema = false)
        => GetOwnedConnection(schema, authority.Validate);

    internal string BindAuthority(BindingAuthority authority) => BindEntry(authority.Validate);
}
