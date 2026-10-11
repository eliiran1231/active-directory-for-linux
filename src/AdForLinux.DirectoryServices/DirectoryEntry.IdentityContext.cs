using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    internal IdentityContextLifetime IdentityLifetime { get; } = new();
    internal string IdentityTarget => _path.DistinguishedName;
    // Internal controlled-transport seam; the shipped default is the AD LDAP resolver.
    internal Func<LdapConnectionOptions, IIdentitySearchSession> IdentitySessionFactory { get; set; }
        = static options => LdapExceptionTranslator.Execute(() => new LdapIdentitySearchSession(options));
    internal Func<string[], bool, PropertyCollection>? PropertyReadOverride { get; set; }
}
