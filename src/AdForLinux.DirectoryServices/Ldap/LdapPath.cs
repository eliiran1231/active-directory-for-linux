namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// A parsed <c>LDAP://host:port/DistinguishedName</c> path.
///
/// Examples we accept:
///   LDAP://dc1.example.com/DC=example,DC=com
///   LDAP://dc1.example.com:636/CN=Jeff,CN=Users,DC=example,DC=com
///   LDAP://DC=example,DC=com            (no host — needs a default server)
/// </summary>
internal sealed record LdapPath(string? Host, int? Port, string DistinguishedName)
{
    private const string Scheme = "LDAP://";

    public bool HasHost => !string.IsNullOrEmpty(Host);

    public static LdapPath Parse(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var schemeSeparator = path.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator > 0 && IsProviderScheme(path.AsSpan(0, schemeSeparator)))
        {
            var providerScheme = path.Substring(0, schemeSeparator);
            if (!providerScheme.Equals("LDAP", StringComparison.OrdinalIgnoreCase))
            {
                throw new PlatformNotSupportedException(
                    $"The directory provider scheme '{providerScheme}://' is not supported. " +
                    "Only LDAP:// paths are supported; configure LDAPS with " +
                    "AuthenticationTypes.SecureSocketsLayer or LDAP port 636.");
            }
        }

        var rest = path.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase)
            ? path.Substring(Scheme.Length)
            : path;

        // A DN never contains '/', so the first '/' (if any) splits the
        // authority (host[:port]) from the DN.
        var slash = rest.IndexOf('/');
        if (slash < 0)
        {
            // No slash: either "DC=..." (DN, no host) or a bare "host".
            return rest.Contains('=')
                ? new LdapPath(null, null, rest)
                : new LdapPath(SplitHost(rest).Host, SplitHost(rest).Port, string.Empty);
        }

        var authority = rest.Substring(0, slash);
        var dn = rest.Substring(slash + 1);
        var (host, port) = SplitHost(authority);
        return new LdapPath(host, port, dn);
    }

    private static bool IsProviderScheme(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || !char.IsAsciiLetter(value[0]))
        {
            return false;
        }

        foreach (var character in value[1..])
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not '+' and not '-' and not '.')
            {
                return false;
            }
        }

        return true;
    }

    private static (string? Host, int? Port) SplitHost(string authority)
    {
        if (string.IsNullOrEmpty(authority))
        {
            return (null, null);
        }

        var colon = authority.LastIndexOf(':');
        if (colon > 0 && int.TryParse(authority.Substring(colon + 1), out var port))
        {
            return (authority.Substring(0, colon), port);
        }

        return (authority, null);
    }

    /// <summary>Rebuilds the canonical path string for this parsed value.</summary>
    public override string ToString()
    {
        if (!HasHost)
        {
            return $"{Scheme}{DistinguishedName}";
        }

        var hostPart = Port is { } p ? $"{Host}:{p}" : Host;
        return string.IsNullOrEmpty(DistinguishedName)
            ? $"{Scheme}{hostPart}"
            : $"{Scheme}{hostPart}/{DistinguishedName}";
    }
}
