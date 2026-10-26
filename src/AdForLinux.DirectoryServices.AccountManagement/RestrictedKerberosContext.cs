using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Explicit restricted-profile selection without changing existing context constructors.</summary>
public static class RestrictedKerberosContext
{
    /// <summary>
    /// Creates an inert domain context using the profile's exact endpoint and FILE
    /// source. No cache or deployment is opened. Directory operations currently
    /// throw PlatformNotSupportedException because production activation is disabled.
    /// Alternate credential validation and cross-authority discovery are unavailable.
    /// </summary>
    public static PrincipalContext Create(RestrictedKerberosProfile profile, string? container = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new PrincipalContext(profile, container);
    }
}
