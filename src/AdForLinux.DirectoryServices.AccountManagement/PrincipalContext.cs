using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Text;

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
    private readonly object _containerDiscoveryLock = new();
    private readonly object _connectionStateLock = new();
    private readonly object _foreignContextLock = new();
    private readonly Dictionary<string, PrincipalContext> _foreignContexts =
        new(StringComparer.OrdinalIgnoreCase);
    private CredentialValidationMethod _lastCredentialValidationMethod =
        CredentialValidationMethod.SimpleBindOverSsl;
    private string? _container;
    private string? _connectedServer;
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
            if (_connectedServer is not null)
            {
                return _connectedServer;
            }

            lock (_connectionStateLock)
            {
                CheckDisposed();
                return _connectedServer ??=
                    AccountManagementExceptionTranslator.Execute(DiscoverConnectedServer);
            }
        }
    }

    /// <summary>The explicitly configured container, or null when none was supplied.</summary>
    public string? Container
    {
        get
        {
            CheckDisposed();
            return _container;
        }
    }

    /// <summary>
    /// The search base. A context without an explicit container searches the whole domain,
    /// even though new principals are created in the domain's well-known containers.
    /// </summary>
    internal string QueryContainer => _container ?? DefaultNamingContext;

    /// <summary>Gets the Microsoft-compatible creation container for a principal type.</summary>
    internal string GetCreationContainer(Type principalType)
    {
        CheckDisposed();
        if (_container is not null)
        {
            return _container;
        }

        EnsureWellKnownContainers();
        return typeof(ComputerPrincipal).IsAssignableFrom(principalType)
            ? _computerContainer!
            : _userContainer!;
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
    private string? _userContainer;
    private string? _computerContainer;

    /// <summary>The forest-root naming context used as the GC search base.</summary>
    internal string RootDomainNamingContext
    {
        get
        {
            CheckDisposed();
            return _rootDomainNamingContext ??= DiscoverRootDomainNamingContext();
        }
    }

    private string? _rootDomainNamingContext;

    /// <summary>Whether the connected DC exposes its global-catalog endpoint.</summary>
    internal bool CanUseGlobalCatalog
    {
        get
        {
            CheckDisposed();
            if (_canUseGlobalCatalog is not null)
            {
                return _canUseGlobalCatalog.Value;
            }

            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connect = client.ConnectAsync(_name, _useSsl ? 3269 : 3268);
                _canUseGlobalCatalog = connect.Wait(TimeSpan.FromSeconds(1)) && client.Connected;
            }
            catch (Exception exception) when (
                exception is System.Net.Sockets.SocketException or AggregateException)
            {
                _canUseGlobalCatalog = false;
            }

            return _canUseGlobalCatalog.Value;
        }
    }

    private bool? _canUseGlobalCatalog;

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
            catch (LdapException ex) when (IsAuthenticationFailure(ex))
            {
                // The server reached by this method conclusively rejected the
                // credentials. Trying a platform-unsupported alternate method
                // must not turn an ordinary rejection into an exception.
                return false;
            }
            catch (DirectoryOperationException ex) when (IsAuthenticationFailure(ex))
            {
                return false;
            }
            catch (LdapException ex) when (ShouldTryAlternateValidationMethod(ex))
            {
                // The endpoint or authentication method may be unavailable;
                // try the other validation method below.
            }
            catch (DirectoryOperationException ex)
                when (first == CredentialValidationMethod.SimpleBindOverSsl &&
                    ShouldTryAlternateValidationMethod(ex))
            {
                // Microsoft's Simple+SSL path can report method/transport
                // mismatch as a DirectoryOperationException.
            }
            catch (Exception ex) when (LdapExceptionTranslator.IsProtocolFailure(ex))
            {
                throw AccountManagementExceptionTranslator.TranslateProtocol(ex);
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
            catch (DirectoryOperationException ex) when (IsAuthenticationFailure(ex))
            {
                return false;
            }
            catch (Exception ex) when (LdapExceptionTranslator.IsProtocolFailure(ex))
            {
                throw AccountManagementExceptionTranslator.TranslateProtocol(ex);
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
        catch (Exception ex) when (LdapExceptionTranslator.IsProtocolFailure(ex))
        {
            throw AccountManagementExceptionTranslator.TranslateProtocol(ex);
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

    /// <summary>Opens the same server's global-catalog endpoint.</summary>
    internal DirectoryEntry CreateGlobalCatalogEntry(string distinguishedName)
    {
        CheckDisposed();
        var options = BuildOptions();
        return new DirectoryEntry(
            $"LDAP://{_name}:{(_useSsl ? 3269 : 3268)}/{distinguishedName}",
            new LdapConnectionOptions
            {
                Host = options.Host,
                Port = _useSsl ? 3269 : 3268,
                UseSsl = options.UseSsl,
                AuthenticationType = options.AuthenticationType,
                Signing = options.Signing,
                Sealing = options.Sealing,
                BindDn = options.BindDn,
                BindPassword = options.BindPassword,
            });
    }

    /// <summary>
    /// Opens (and retains) a context for a trusted domain using the credentials
    /// and bind policy of this context. Cross-store principals keep this context
    /// after the membership enumerator which found them has moved on.
    /// </summary>
    internal PrincipalContext GetForeignDomainContext(string domainName)
    {
        CheckDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(domainName);
        if (ForeignPrincipalResolver.TryGetDnsDomainName(DefaultNamingContext)
            ?.Equals(domainName, StringComparison.OrdinalIgnoreCase) == true)
        {
            return this;
        }

        lock (_foreignContextLock)
        {
            if (!_foreignContexts.TryGetValue(domainName, out var context))
            {
                context = new PrincipalContext(
                    ContextType.Domain,
                    domainName,
                    container: null,
                    _options,
                    _userName,
                    _password);
                _foreignContexts.Add(domainName, context);
            }

            return context;
        }
    }

    private string DiscoverDefaultNamingContext() =>
        AccountManagementExceptionTranslator.Execute(DiscoverDefaultNamingContextCore);

    private string DiscoverConnectedServer()
    {
        try
        {
            using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
            return RootDse.GetConnectedServerName(connection);
        }
        catch (Exception exception) when (LdapExceptionTranslator.IsProtocolFailure(exception))
        {
            throw AccountManagementExceptionTranslator.TranslateProtocol(exception);
        }
    }

    private string DiscoverDefaultNamingContextCore()
    {
        try
        {
            using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
            return RootDse.GetDefaultNamingContext(connection)
                ?? throw new InvalidOperationException("The server did not report a default naming context.");
        }
        catch (Exception ex) when (LdapExceptionTranslator.IsProtocolFailure(ex))
        {
            throw AccountManagementExceptionTranslator.TranslateProtocol(ex);
        }
    }

    private string DiscoverRootDomainNamingContext()
    {
        using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
        var values = RootDse.Read(connection, "rootDomainNamingContext");
        return values.TryGetValue("rootDomainNamingContext", out var namingContext)
            ? namingContext
            : DefaultNamingContext;
    }
    private void EnsureWellKnownContainers()
    {
        if (_userContainer is not null && _computerContainer is not null)
        {
            return;
        }

        lock (_containerDiscoveryLock)
        {
            if (_userContainer is not null && _computerContainer is not null)
            {
                return;
            }

            using var connection = LdapConnectionFactory.CreateBound(BuildOptions());
            var request = new SearchRequest(
                DefaultNamingContext,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Base,
                "wellKnownObjects");
            var response = (SearchResponse)connection.SendRequest(request);

            string? users = null;
            string? computers = null;
            if (response.Entries.Count > 0 &&
                response.Entries[0].Attributes["wellKnownObjects"] is { } values)
            {
                TryResolveWellKnownContainers(values.Cast<object?>(), out users, out computers);
            }

            if (users is null || computers is null)
            {
                throw new PrincipalOperationException(
                    "The domain did not report its well-known Users and Computers containers.");
            }

            _userContainer = users;
            _computerContainer = computers;
        }
    }

    private const string UsersContainerIdentifier = "A9D1CA15768811D1ADED00C04FD8D5CD";
    private const string ComputersContainerIdentifier = "AA312825768811D1ADED00C04FD8D5CD";

    internal static bool TryResolveWellKnownContainers(
        IEnumerable<object?> values,
        out string? users,
        out string? computers)
    {
        users = null;
        computers = null;
        foreach (var value in values)
        {
            if (!TryParseDnWithBinary(value, out var identifier, out var distinguishedName))
            {
                continue;
            }

            if (identifier.Equals(UsersContainerIdentifier, StringComparison.OrdinalIgnoreCase))
            {
                users = distinguishedName;
            }
            else if (identifier.Equals(ComputersContainerIdentifier, StringComparison.OrdinalIgnoreCase))
            {
                computers = distinguishedName;
            }
        }

        return users is not null && computers is not null;
    }

    internal static bool TryParseDnWithBinary(
        object? value,
        out string identifier,
        out string distinguishedName)
    {
        identifier = string.Empty;
        distinguishedName = string.Empty;

        var text = value switch
        {
            string stringValue => stringValue,
            byte[] bytes => Encoding.UTF8.GetString(bytes),
            _ => null,
        };
        if (text is null || !text.StartsWith("B:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var lengthSeparator = text.IndexOf(':', 2);
        if (lengthSeparator < 0 ||
            !int.TryParse(text.AsSpan(2, lengthSeparator - 2), out var identifierLength) ||
            identifierLength <= 0)
        {
            return false;
        }

        var dnSeparator = text.IndexOf(':', lengthSeparator + 1);
        if (dnSeparator < 0 || dnSeparator - lengthSeparator - 1 != identifierLength)
        {
            return false;
        }

        identifier = text.Substring(lengthSeparator + 1, identifierLength);
        distinguishedName = text.Substring(dnSeparator + 1);
        return distinguishedName.Length > 0;
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

    private static bool IsAuthenticationFailure(DirectoryOperationException exception) =>
        (int?)exception.Response?.ResultCode == 49;

    private static bool ShouldTryAlternateValidationMethod(LdapException exception) =>
        exception.ErrorCode is
            7 or   // auth method not supported
            8 or   // strong authentication required
            13 or  // confidentiality required
            48 or  // inappropriate authentication
            52 or  // server endpoint unavailable
            81 or  // server down
            85 or  // timeout
            86 or  // unknown authentication method
            91 or  // connect error
            92 or  // operation not supported
            112;   // TLS is not supported

    private static bool ShouldTryAlternateValidationMethod(
        DirectoryOperationException exception) =>
        (int?)exception.Response?.ResultCode is 7 or 8 or 13 or 48 or 52;

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

        lock (_foreignContextLock)
        {
            foreach (var context in _foreignContexts.Values)
            {
                context.Dispose();
            }

            _foreignContexts.Clear();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
