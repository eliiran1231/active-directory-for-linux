using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The server and account a set of principal operations run against, like
/// Microsoft's <c>PrincipalContext</c>.
///
/// Linux notes: there is no serverless binding, so you must pass the domain
/// controller name. Binding is a simple bind over TLS.
/// </summary>
public class PrincipalContext : IDisposable
{
    private readonly ContextOptions _options;
    private string? _container;

    /// <summary>Current-domain context. Not supported on Linux — pass a server name.</summary>
    public PrincipalContext(ContextType contextType)
        : this(contextType, null, null, DefaultOptions, null, null)
    {
    }

    /// <summary>Context for a named server (and optional <c>host:port</c>).</summary>
    public PrincipalContext(ContextType contextType, string? name)
        : this(contextType, name, null, DefaultOptions, null, null)
    {
    }

    /// <summary>Context scoped to a container (base DN) on a server.</summary>
    public PrincipalContext(ContextType contextType, string? name, string? container)
        : this(contextType, name, container, DefaultOptions, null, null)
    {
    }

    /// <summary>Authenticated context (simple bind) scoped to a container.</summary>
    public PrincipalContext(ContextType contextType, string? name, string? container, string? userName, string? password)
        : this(contextType, name, container, DefaultOptions, userName, password)
    {
    }

    /// <summary>Full constructor with bind options.</summary>
    public PrincipalContext(
        ContextType contextType,
        string? name,
        string? container,
        ContextOptions options,
        string? userName,
        string? password)
    {
        if (contextType != ContextType.Domain)
        {
            throw new NotSupportedException(
                $"This Linux port supports ContextType.Domain only, not {contextType}.");
        }

        if (string.IsNullOrEmpty(name))
        {
            throw new NotSupportedException(
                "Serverless binding is not supported on Linux. Pass the domain controller " +
                "name, e.g. new PrincipalContext(ContextType.Domain, \"dc1.example.com\").");
        }

        ContextType = contextType;
        _options = options;
        UserName = userName;
        _password = password;

        UseSsl = options.HasFlag(ContextOptions.SecureSocketLayer);
        (Name, Port) = ParseServer(name, UseSsl);
        _container = container;
    }

    private readonly string? _password;

    private const ContextOptions DefaultOptions =
        ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer;

    /// <summary>The store type. Always Domain here.</summary>
    public ContextType ContextType { get; }

    /// <summary>The server host name.</summary>
    public string Name { get; }

    /// <summary>The port used to reach the server.</summary>
    public int Port { get; }

    /// <summary>Whether the connection uses TLS.</summary>
    public bool UseSsl { get; }

    /// <summary>The bind user, or null for an anonymous context.</summary>
    public string? UserName { get; }

    /// <summary>The server this context is connected to.</summary>
    public string ConnectedServer => Name;

    /// <summary>
    /// The container (base DN) for searches. If none was given, it is discovered
    /// from the server's default naming context on first use.
    /// </summary>
    public string Container => _container ??= DefaultNamingContext;

    /// <summary>
    /// The domain root DN, whatever <see cref="Container"/> is scoped to.
    /// Domain-wide settings such as the lockout policy live here.
    /// </summary>
    internal string DefaultNamingContext => _defaultNamingContext ??= DiscoverDefaultNamingContext();

    private string? _defaultNamingContext;

    /// <summary>
    /// Checks a username and password by trying a bind. Returns true if it
    /// succeeds, false if the credentials are rejected.
    /// </summary>
    public bool ValidateCredentials(string userName, string password)
    {
        try
        {
            using var connection = LdapConnectionFactory.CreateBound(BuildOptions(userName, password));
            return true;
        }
        catch (System.DirectoryServices.Protocols.LdapException)
        {
            return false;
        }
    }

    internal LdapConnectionOptions BuildOptions() => BuildOptions(UserName, _password);

    internal LdapConnectionOptions BuildOptions(string? bindUser, string? bindPassword) => new()
    {
        Host = Name,
        Port = Port,
        UseSsl = UseSsl,
        BindDn = bindUser,
        BindPassword = bindPassword,
    };

    /// <summary>The LDAP path for a DN on this context's server.</summary>
    internal string PathFor(string distinguishedName)
    {
        var authority = $"{Name}:{Port}";
        return string.IsNullOrEmpty(distinguishedName)
            ? $"LDAP://{authority}"
            : $"LDAP://{authority}/{distinguishedName}";
    }

    /// <summary>Opens a DirectoryEntry for a DN, using this context's credentials.</summary>
    internal DirectoryEntry CreateDirectoryEntry(string distinguishedName)
    {
        var auth = UseSsl ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.None;
        return new DirectoryEntry(PathFor(distinguishedName), UserName, _password, auth);
    }

    private string DiscoverDefaultNamingContext()
    {
        using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
        return RootDse.GetDefaultNamingContext(connection)
            ?? throw new InvalidOperationException("The server did not report a default naming context.");
    }

    private static (string Host, int Port) ParseServer(string name, bool useSsl)
    {
        var colon = name.LastIndexOf(':');
        if (colon > 0 && int.TryParse(name.Substring(colon + 1), out var port))
        {
            return (name.Substring(0, colon), port);
        }

        return (name, useSsl ? 636 : 389);
    }

    public void Dispose() => GC.SuppressFinalize(this);
}
