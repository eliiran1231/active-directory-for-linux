using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Opens and binds an <see cref="LdapConnection"/> from
/// <see cref="LdapConnectionOptions"/>. Simple bind over TLS.
/// </summary>
internal static class LdapConnectionFactory
{
    /// <summary>
    /// Creates a bound connection. The caller owns it and must dispose it.
    /// Throws <see cref="LdapException"/> or <see cref="DirectoryOperationException"/>
    /// if the bind fails, just like the real client would.
    /// </summary>
    public static LdapConnection CreateBound(LdapConnectionOptions options)
    {
        var identifier = new LdapDirectoryIdentifier(options.Host, options.Port);
        var connection = new LdapConnection(identifier)
        {
            AuthType = options.IsAnonymous ? AuthType.Anonymous : AuthType.Basic,
        };

        connection.SessionOptions.ProtocolVersion = 3;

        if (options.SkipCertificateCheck)
        {
            ConfigureCertificateSkip(connection);
        }

        if (options.UseSsl)
        {
            // LDAPS: TLS wraps the socket from the start (port 636).
            connection.SessionOptions.SecureSocketLayer = true;
        }

        var credential = options.ToCredential();
        if (credential is not null)
        {
            connection.Credential = credential;
        }

        // The connection stays open until disposed; bind eagerly so failures
        // surface here rather than on first search.
        connection.Timeout = TimeSpan.FromSeconds(30);

        if (options.UseStartTls && !options.UseSsl)
        {
            // StartTLS: connect in the clear (port 389), then upgrade to TLS.
            connection.SessionOptions.StartTransportLayerSecurity(null);
        }

        connection.Bind();
        return connection;
    }

    /// <summary>
    /// Turns off TLS certificate verification, the right way for each platform.
    ///
    /// On Windows the managed <c>VerifyServerCertificate</c> callback works and
    /// is the clean way. On Linux/macOS the client is native OpenLDAP: setting
    /// that callback actually breaks the TLS handshake, and cert checking is
    /// controlled by <c>LDAPTLS_REQCERT</c> (or ldap.conf), which OpenLDAP reads
    /// from the environment at start-up. So there we rely on that variable —
    /// set it to <c>never</c> before launching the process (docker-compose does
    /// this for the tests). We also set it here as a best effort, though it may
    /// be too late if the native library already read it.
    /// </summary>
    private static void ConfigureCertificateSkip(LdapConnection connection)
    {
        if (OperatingSystem.IsWindows())
        {
            connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
        }
        else
        {
            Environment.SetEnvironmentVariable("LDAPTLS_REQCERT", "never");
        }
    }
}
