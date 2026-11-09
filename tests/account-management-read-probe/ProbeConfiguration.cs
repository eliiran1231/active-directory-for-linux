namespace AdForLinux.ReadProbe;

// Pure admission parser, linked into the guarded functional tests. No secrets,
// environment access, LDAP handles or process creation in this type.
internal sealed record ProbeConfiguration(string Host, string FixtureDn, string SchemaDn, string Sam, Guid Guid)
{
    internal static ProbeConfiguration Parse(string[] arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var optIn = false;
        foreach (var argument in arguments)
            if (argument.Any(char.IsControl) || argument.Length > 4096) throw new ArgumentException();
        for (var index = 0; index < arguments.Length; index++)
        {
            var key = arguments[index];
            if (key == "--allow-live-read")
            {
                if (optIn) throw new ArgumentException();
                optIn = true; continue;
            }
            if (key is not ("--host" or "--port" or "--fixture-dn" or "--schema-dn" or "--sam" or "--guid")
                || index + 1 == arguments.Length || !values.TryAdd(key, arguments[++index])) throw new ArgumentException();
        }
        if (!optIn || values.Count != 6 || values["--port"] != "636"
            || Uri.CheckHostName(values["--host"]) != UriHostNameType.Dns
            || values["--host"].EndsWith('.') || values["--host"].Contains(':') || !values["--host"].Contains('.')
            || values["--host"].Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-'))
            || string.IsNullOrWhiteSpace(values["--sam"])
            || !Guid.TryParseExact(values["--guid"], "D", out var guid) || guid == Guid.Empty)
            throw new ArgumentException();
        foreach (var key in new[] { "--fixture-dn", "--schema-dn" })
            if (string.IsNullOrWhiteSpace(values[key]) || !values[key].Contains('=')
                || values[key].Contains('/') || values[key].Contains('<')) throw new ArgumentException();
        return new(values["--host"], values["--fixture-dn"], values["--schema-dn"], values["--sam"], guid);
    }
}
