using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Opens and binds an <see cref="LdapConnection"/> from
/// <see cref="LdapConnectionOptions"/>.
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
        var connection = Create(options);
        try
        {
            connection.Bind();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Creates and configures a connection without binding it.</summary>
    internal static LdapConnection Create(LdapConnectionOptions options)
    {
        var identifier = new LdapDirectoryIdentifier(options.Host, options.Port);
        var connection = new LdapConnection(identifier)
        {
            AuthType = options.IsAnonymous ? AuthType.Anonymous : options.AuthenticationType,
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

        // On OpenLDAP, even assigning false can force early server access.
        // Leave the platform defaults alone unless the caller requested these.
        if (options.Signing)
        {
            connection.SessionOptions.Signing = true;
        }

        if (options.Sealing)
        {
            connection.SessionOptions.Sealing = true;
        }

        var credential = options.ToCredential();
        if (credential is not null)
        {
            connection.Credential = credential;
        }

        // The connection stays open until disposed; bind eagerly so failures
        // surface here rather than on first search.
        connection.Timeout = options.Timeout;

        if (options.UseStartTls && !options.UseSsl)
        {
            // StartTLS: connect in the clear (port 389), then upgrade to TLS.
            connection.SessionOptions.StartTransportLayerSecurity(null);
        }

        return connection;
    }

    /// <summary>
    /// Turns off TLS certificate verification, the right way for each platform.
    ///
    /// On Windows the managed <c>VerifyServerCertificate</c> callback works and
    /// is the clean way. On Linux/macOS the client is native OpenLDAP: setting
    /// that callback actually breaks the TLS handshake, and cert checking is
    /// controlled by <c>LDAPTLS_REQCERT</c> (or ldap.conf), which OpenLDAP reads
    /// from the environment at start-up. The variable must therefore already
    /// be <c>never</c> before launching the process (docker-compose does this
    /// for the tests). Never change it here: that would weaken certificate
    /// validation process-wide, including for unrelated connections.
    /// </summary>
    private static void ConfigureCertificateSkip(LdapConnection connection)
    {
        if (OperatingSystem.IsWindows())
        {
            connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
        }
        else
        {
            EnsureOpenLdapCertificateSkipIsConfigured(
                Environment.GetEnvironmentVariable("LDAPTLS_REQCERT"));
        }
    }

    internal static void EnsureOpenLdapCertificateSkipIsConfigured(string? certificateRequirement)
    {
        if (string.Equals(certificateRequirement?.Trim(), "never", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new PlatformNotSupportedException(
            "SkipCertificateCheck cannot be configured per connection on Linux or macOS. " +
            "Start the process with LDAPTLS_REQCERT=never (or configure ldap.conf) before opening any LDAP connections.");
    }
}
