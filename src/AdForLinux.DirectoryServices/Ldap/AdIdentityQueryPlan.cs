using System.Text;
using AdForLinux.Security.Principal;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

// One exact assertion within one supplied domain. No domain discovery, endpoint,
// session, credentials, lease or execution callback belongs in a plan.
internal sealed class AdIdentityQueryPlan
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal string NamingContext { get; }
    internal string Filter { get; }
    internal ProtocolScope Scope => ProtocolScope.Subtree;
    internal string[] GetAttributes() => ["objectSid", "sAMAccountName", "objectClass", "distinguishedName"];

    private AdIdentityQueryPlan(string namingContext, string assertion)
    { NamingContext = namingContext; Filter = "(&(objectClass=*)" + assertion + ")"; }

    internal static AdIdentityQueryPlan Create(AdIdentityDomainMetadata domain, IdentityReference identity)
    {
        string assertion;
        if (identity is SecurityIdentifier sid)
        {
            var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            assertion = "(objectSid=" + Escape(bytes) + ")";
        }
        else
        {
            var name = identity.Value;
            var slash = name.IndexOf('\\');
            if (slash >= 0)
            {
                var qualifier = name[..slash]; name = name[(slash + 1)..];
                if (name.Contains('\\') || name.Length == 0 ||
                    (!qualifier.Equals(domain.NetbiosName, StringComparison.OrdinalIgnoreCase)
                        && !qualifier.Equals(domain.DnsName, StringComparison.OrdinalIgnoreCase)))
                    throw new NotSupportedException("The account qualifier is outside the verified domain scope.");
                assertion = "(sAMAccountName=" + EscapeText(name) + ")";
            }
            // An alternate UPN suffix is part of an exact value, never a routing hint.
            else assertion = "(" + (name.Contains('@') ? "userPrincipalName" : "sAMAccountName") + "=" + EscapeText(name) + ")";
        }
        return new(domain.NamingContext, assertion);
    }

    internal static string EscapeText(string value) => Escape(Utf8.GetBytes(value));
    private static string Escape(byte[] bytes) => string.Concat(bytes.Select(b => "\\" + b.ToString("x2")));
}
