using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Resolves a store-local foreignSecurityPrincipal into its issuing store.</summary>
internal static class ForeignPrincipalResolver
{
    internal static Principal ResolveOrCreateFallback(
        PrincipalContext context,
        DirectoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(entry);

        return AccountManagementExceptionTranslator.Execute(() =>
        {
            if (entry.Properties["objectSid"].Value is not byte[] sid)
            {
                entry.Dispose();
                throw new PrincipalOperationException(
                    "The security identifier for the cross-store group member could not be read.");
            }

            var issuer = FindIssuerDomain(context, sid);
            if (issuer is null)
            {
                // LookupSid returns no issuer for well-known and genuinely
                // unknown SIDs. Microsoft's enumerator returns a fake/unknown
                // principal in that case; retain our store-local wrapper.
                return new ForeignSecurityPrincipal(context, entry);
            }

            try
            {
                var remoteContext = context.GetForeignDomainContext(issuer);
                var principal = Principal.FindByIdentity(
                    remoteContext,
                    IdentityType.Sid,
                    SidCodec.Format(sid));
                if (principal is null)
                {
                    throw new PrincipalOperationException(
                        "The cross-store principal could not be found in its issuing domain.");
                }

                entry.Dispose();
                return principal;
            }
            catch
            {
                entry.Dispose();
                throw;
            }
        });
    }

    private static string? FindIssuerDomain(PrincipalContext context, byte[] sid)
    {
        var domainSid = TryGetAccountDomainSid(sid);
        if (domainSid is not null)
        {
            using var system = context.CreateDirectoryEntry(
                $"CN=System,{context.DefaultNamingContext}");
            using var searcher = new DirectorySearcher(
                system,
                $"(&(objectClass=trustedDomain)(securityIdentifier={LdapFilter.EscapeBytes(domainSid)}))",
                new[] { "trustPartner" },
                SearchScope.Subtree)
            {
                SizeLimit = 1,
            };
            using var result = searcher.FindOne()?.GetDirectoryEntry();
            if (result?.Properties["trustPartner"].Value is string trustPartner
                && !string.IsNullOrWhiteSpace(trustPartner))
            {
                return trustPartner;
            }
        }

        // A forest GC knows every real object in the forest, but not principals
        // across an external forest trust. Excluding FSPs prevents resolving the
        // SID straight back to the local placeholder.
        if (!context.CanUseGlobalCatalog)
        {
            return null;
        }

        try
        {
            using var root = context.CreateGlobalCatalogEntry(context.RootDomainNamingContext);
            using var gcSearcher = new DirectorySearcher(
                root,
                $"(&(objectSid={LdapFilter.EscapeBytes(sid)})(!(objectClass=foreignSecurityPrincipal)))",
                new[] { "distinguishedName" },
                SearchScope.Subtree)
            {
                SizeLimit = 1,
            };
            using var actual = gcSearcher.FindOne()?.GetDirectoryEntry();
            return actual?.Properties["distinguishedName"].Value is string distinguishedName
                ? TryGetDnsDomainName(distinguishedName)
                : null;
        }
        catch (Exception exception) when (
            exception is LdapException or DirectoryOperationException)
        {
            // GC discovery is an optional second route after the trusted-domain
            // object lookup. Its endpoint being unavailable does not turn an
            // otherwise untranslatable SID into a server failure.
            return null;
        }
    }

    internal static byte[]? TryGetAccountDomainSid(byte[] sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        if (sid.Length != 28 || sid[0] != 1 || sid[1] != 5
            || sid[2] != 0 || sid[3] != 0 || sid[4] != 0
            || sid[5] != 0 || sid[6] != 0 || sid[7] != 5
            || sid[8] != 21 || sid[9] != 0 || sid[10] != 0 || sid[11] != 0
            || sid.Length != 8 + (sid[1] * 4))
        {
            return null;
        }

        var result = sid[..^4];
        result[1]--;
        return result;
    }

    internal static string? TryGetDnsDomainName(string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(distinguishedName);
        var labels = new List<string>();
        string? remaining = distinguishedName;
        while (remaining is not null)
        {
            var rdn = LdapDistinguishedName.RelativeName(remaining);
            if (rdn.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)
                && rdn.Length > 3)
            {
                labels.Add(rdn[3..]);
            }
            else if (labels.Count > 0)
            {
                // DC components must be the contiguous naming-context suffix.
                return null;
            }

            remaining = LdapDistinguishedName.Parent(remaining);
        }

        return labels.Count == 0 ? null : string.Join('.', labels);
    }
}
