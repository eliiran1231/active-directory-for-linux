using AdForLinux.DirectoryServices;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>Explicit restricted-profile selection without changing existing context constructors.</summary>
public static class RestrictedKerberosContext
{
    /// <summary>
    /// Creates an inert domain context using the profile's exact endpoint and FILE
    /// source. Construction opens no cache or deployment. Operations require
    /// the admitted private worker composition and never fall back to ambient identity.
    /// Alternate credential validation and cross-authority discovery are unavailable.
    /// </summary>
    public static PrincipalContext Create(RestrictedKerberosProfile profile, string? container = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new PrincipalContext(profile, container);
    }
}
