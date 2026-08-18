using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using System.ComponentModel;
using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// The server and account a set of principal operations run against, like
/// Microsoft's <c>PrincipalContext</c>.
///
/// Linux notes: there is no serverless binding, so you must pass the domain
/// controller name. Simple and negotiate LDAP authentication are selected with
/// <see cref="ContextOptions"/>.
/// </summary>
public class PrincipalContext : IDisposable
{
    private readonly ContextOptions _options;
    private readonly bool _hasExplicitPort;
    private readonly ContextType _contextType;
    private readonly string _name;
    private readonly int _port;
    private readonly bool _useSsl;
    private readonly string? _userName;
    private readonly object _credentialValidationLock = new();
    private CredentialValidationMethod _lastCredentialValidationMethod =
        CredentialValidationMethod.SimpleBindOverSsl;
    private string? _container;
    private bool _disposed;

    private enum CredentialValidationMethod
    {
        SimpleBindOverSsl,
        Negotiate,
    }

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

    /// <summary>Context for a named server using explicit bind credentials.</summary>
    public PrincipalContext(
        ContextType contextType,
        string? name,
        string? userName,
        string? password)
        : this(contextType, name, null, DefaultOptions, userName, password)
    {
    }

    /// <summary>Context scoped to a container with explicit bind options.</summary>
    public PrincipalContext(
        ContextType contextType,
        string? name,
        string? container,
        ContextOptions options)
        : this(contextType, name, container, options, null, null)
    {
    }

    /// <summary>Authenticated context scoped to a container.</summary>
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
        if (!Enum.IsDefined(contextType))
        {
            throw new InvalidEnumArgumentException(
                nameof(contextType), (int)contextType, typeof(ContextType));
        }

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

        if ((userName is null) != (password is null))
        {
            throw new ArgumentException(
                "The userName and password parameters must either both be null or both contain a value.");
        }

        ValidateOptions(options);

        _contextType = contextType;
        _options = options;
        _userName = userName;
        _password = password;

        _useSsl = options.HasFlag(ContextOptions.SecureSocketLayer);
        (_name, _port, _hasExplicitPort) = ParseServer(name, _useSsl);
        _container = container;
    }

    private readonly string? _password;

    private const ContextOptions DefaultOptions =
        ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing;

    private const ContextOptions CredentialValidationSimpleOptions =
        ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer;

    private const ContextOptions CredentialValidationNegotiateOptions =
        ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing;

    /// <summary>The store type. Always Domain here.</summary>
    public ContextType ContextType
    {
        get
        {
            CheckDisposed();
            return _contextType;
        }
    }

    /// <summary>The server host name.</summary>
    public string Name
    {
        get
        {
            CheckDisposed();
            return _name;
        }
    }

    /// <summary>The port used to reach the server.</summary>
    public int Port
    {
        get
        {
            CheckDisposed();
            return _port;
        }
    }

    /// <summary>Whether the connection uses TLS.</summary>
    public bool UseSsl
    {
        get
        {
            CheckDisposed();
            return _useSsl;
        }
    }

    /// <summary>The bind user, or null for an anonymous context.</summary>
    public string? UserName
    {
        get
        {
            CheckDisposed();
            return _userName;
        }
    }

    /// <summary>The options used to bind this context.</summary>
    public ContextOptions Options
    {
        get
        {
            CheckDisposed();
            return _options;
        }
    }

    /// <summary>The server this context is connected to.</summary>
    public string ConnectedServer
    {
        get
        {
            CheckDisposed();
            return _name;
        }
    }

    /// <summary>
    /// The container (base DN) for searches. If none was given, it is discovered
    /// from the server's default naming context on first use.
    /// </summary>
    public string Container
    {
        get
        {
            CheckDisposed();
            return _container ??= DefaultNamingContext;
        }
    }

    /// <summary>
    /// The domain root DN, whatever <see cref="Container"/> is scoped to.
    /// Domain-wide settings such as the lockout policy live here.
    /// </summary>
    internal string DefaultNamingContext
    {
        get
        {
            CheckDisposed();
            return _defaultNamingContext ??= DiscoverDefaultNamingContext();
        }
    }

    private string? _defaultNamingContext;

    /// <summary>
    /// Checks a username and password by trying a bind. Returns true if it
    /// succeeds, false if the credentials are rejected.
    /// </summary>
    public bool ValidateCredentials(string userName, string password)
    {
        CheckDisposed();
        ValidateCredentialPair(userName, password);
        if (userName is { Length: 0 })
        {
            return false;
        }

        lock (_credentialValidationLock)
        {
            var first = _lastCredentialValidationMethod;
            var second = first == CredentialValidationMethod.SimpleBindOverSsl
                ? CredentialValidationMethod.Negotiate
                : CredentialValidationMethod.SimpleBindOverSsl;

            try
            {
                BindCredentials(userName, password, OptionsFor(first));
                _lastCredentialValidationMethod = first;
                return true;
            }
            catch (LdapException)
            {
                // Microsoft tries the other credential-validation method even
                // when the first failure looks like invalid credentials.
            }
            catch (DirectoryOperationException)
                when (first == CredentialValidationMethod.SimpleBindOverSsl)
            {
                // Microsoft's Simple+SSL first attempt also falls back for
                // DirectoryOperationException; its Negotiate-first path does not.
            }

            try
            {
                BindCredentials(userName, password, OptionsFor(second));
                _lastCredentialValidationMethod = second;
                return true;
            }
            catch (LdapException ex) when (IsAuthenticationFailure(ex))
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Checks a username and password using the requested bind options.
    /// </summary>
    public bool ValidateCredentials(
        string userName,
        string password,
        ContextOptions options)
    {
        CheckDisposed();
        ValidateCredentialPair(userName, password);

        if (userName is { Length: 0 })
        {
            return false;
        }

        try
        {
            BindCredentials(userName, password, options);
            return true;
        }
        catch (LdapException ex) when (IsAuthenticationFailure(ex))
        {
            return false;
        }
    }

    internal LdapConnectionOptions BuildOptions()
    {
        CheckDisposed();
        return BuildOptions(_userName, _password);
    }

    internal LdapConnectionOptions BuildOptions(string? bindUser, string? bindPassword)
    {
        CheckDisposed();
        return BuildOptions(bindUser, bindPassword, _options);
    }

    private LdapConnectionOptions BuildOptions(
        string? bindUser,
        string? bindPassword,
        ContextOptions options,
        bool useContextPort = true)
    {
        CheckDisposed();
        var useSsl = options.HasFlag(ContextOptions.SecureSocketLayer);
        // The explicit validation overload accepts unusual flag combinations:
        // SimpleBind wins when present, while zero falls back to Negotiate.
        var authenticationType = options.HasFlag(ContextOptions.SimpleBind)
            ? AuthType.Basic
            : AuthType.Negotiate;
        return new LdapConnectionOptions
        {
            Host = _name,
            Port = useContextPort && _hasExplicitPort ? _port : useSsl ? 636 : 389,
            UseSsl = useSsl,
            AuthenticationType = authenticationType,
            Signing = options.HasFlag(ContextOptions.Signing),
            Sealing = options.HasFlag(ContextOptions.Sealing),
            BindDn = bindUser,
            BindPassword = bindPassword,
        };
    }

    /// <summary>The LDAP path for a DN on this context's server.</summary>
    internal string PathFor(string distinguishedName)
    {
        CheckDisposed();
        var authority = $"{_name}:{_port}";
        return string.IsNullOrEmpty(distinguishedName)
            ? $"LDAP://{authority}"
            : $"LDAP://{authority}/{distinguishedName}";
    }

    /// <summary>Opens a DirectoryEntry for a DN, using this context's credentials.</summary>
    internal DirectoryEntry CreateDirectoryEntry(string distinguishedName)
    {
        CheckDisposed();
        return new DirectoryEntry(PathFor(distinguishedName), BuildOptions());
    }

    private string DiscoverDefaultNamingContext()
    {
        using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
        return RootDse.GetDefaultNamingContext(connection)
            ?? throw new InvalidOperationException("The server did not report a default naming context.");
    }

    private static (string Host, int Port, bool HasExplicitPort) ParseServer(
        string name,
        bool useSsl)
    {
        var colon = name.LastIndexOf(':');
        if (colon > 0 && int.TryParse(name.Substring(colon + 1), out var port))
        {
            return (name.Substring(0, colon), port, true);
        }

        return (name, useSsl ? 636 : 389, false);
    }

    private static void ValidateOptions(ContextOptions options)
    {
        const ContextOptions validOptions =
            ContextOptions.Negotiate |
            ContextOptions.SimpleBind |
            ContextOptions.SecureSocketLayer |
            ContextOptions.Signing |
            ContextOptions.Sealing |
            ContextOptions.ServerBind;

        if ((options & ~validOptions) != 0)
        {
            throw new InvalidEnumArgumentException(
                nameof(options), (int)options, typeof(ContextOptions));
        }

        var bindOptions = options & (ContextOptions.Negotiate | ContextOptions.SimpleBind);
        if (bindOptions is ContextOptions.Negotiate or ContextOptions.SimpleBind)
        {
            return;
        }

        throw new ArgumentException(
            "Domain contexts require exactly one of ContextOptions.Negotiate or ContextOptions.SimpleBind.",
            nameof(options));
    }

    private static bool IsAuthenticationFailure(LdapException exception) =>
        exception.ErrorCode is 49 or 1326;

    private static void ValidateCredentialPair(string? userName, string? password)
    {
        if ((userName is null) != (password is null))
        {
            throw new ArgumentException(
                "The userName and password parameters must either both be null or both contain a value.");
        }
    }

    private static ContextOptions OptionsFor(CredentialValidationMethod method) =>
        method == CredentialValidationMethod.SimpleBindOverSsl
            ? CredentialValidationSimpleOptions
            : CredentialValidationNegotiateOptions;

    private void BindCredentials(
        string? userName,
        string? password,
        ContextOptions options)
    {
        using var connection = LdapConnectionFactory.CreateBound(
            BuildOptions(userName, password, options, useContextPort: false));
    }

    internal void CheckDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(PrincipalContext));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
