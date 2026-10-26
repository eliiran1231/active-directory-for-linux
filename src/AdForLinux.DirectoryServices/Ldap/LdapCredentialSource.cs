using System.Text;

namespace AdForLinux.DirectoryServices.Ldap;

internal enum LdapCredentialSourceKind { File = 1, DirectoryCollection = 2 }
// A source recipe, never an identity/credential snapshot or reuse proof. Selection
// must return a cache named within this source before GSS acquisition. This is not
// filesystem confinement and does not sandbox configured cache-selection plugins.
internal sealed record LdapCredentialSource(LdapCredentialSourceKind Kind, string AbsolutePath)
{
    internal void Validate()
    {
        if (Kind is not LdapCredentialSourceKind.File and not LdapCredentialSourceKind.DirectoryCollection)
            throw new PlatformNotSupportedException("Only explicit FILE and DIR collection sources are represented.");
        if (string.IsNullOrEmpty(AbsolutePath) || !AbsolutePath.StartsWith('/') || AbsolutePath.Contains('\0') ||
            AbsolutePath.Split('/').Skip(1).Any(component => component.Length == 0 || component is "." or ".."))
            throw new ArgumentException("Credential source requires a non-root absolute POSIX path without empty or dot components.");
        if (new UTF8Encoding(false, true).GetByteCount(AbsolutePath) > 4096)
            throw new ArgumentException("Credential source path exceeds the supported length.");
    }
}
