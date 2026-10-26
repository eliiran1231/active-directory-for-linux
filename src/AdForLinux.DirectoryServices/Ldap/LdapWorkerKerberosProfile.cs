using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

// Deliberately restricted policy, not a transparent copy of host krb5.conf.
// There are no raw fragments, includes, module entries, KDC endpoints or k5identity.
// The path is a recipe: private compiled legacy plugin paths still require review.
internal sealed record LdapWorkerKerberosProfile(string DefaultRealm, string ServiceHost, string PrivatePluginDirectory)
{
    internal const int MaximumBytes = 32768;
    internal byte[] Generate(string targetHost)
    {
        if (string.IsNullOrEmpty(DefaultRealm) || DefaultRealm.Length > 253 ||
            DefaultRealm.Any(c => !(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_')) ||
            string.IsNullOrEmpty(ServiceHost) || ServiceHost.Length > 253 ||
            !string.Equals(ServiceHost, targetHost, StringComparison.OrdinalIgnoreCase) ||
            ServiceHost.Split('.').Any(label => label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("Restricted Kerberos configuration requires an ASCII realm and exact DNS target.");
        new LdapCredentialSource(LdapCredentialSourceKind.DirectoryCollection, PrivatePluginDirectory).Validate();
        if (PrivatePluginDirectory.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '/' and not '.' and not '-' and not '_'))
            throw new ArgumentException("Restricted plugin path cannot contain configuration syntax or expansion tokens.");
        var text = $$"""
            [libdefaults]
             default_realm = {{DefaultRealm}}
             dns_lookup_realm = false
             dns_lookup_kdc = false
             dns_canonicalize_hostname = false
             rdns = false
             canonicalize = false
             qualify_shortname = ""
             plugin_base_dir = {{PrivatePluginDirectory}}
            [domain_realm]
             {{ServiceHost.ToLowerInvariant()}} = {{DefaultRealm}}
            [plugins]
             ccselect = {
              enable_only = realm
             }
            """ + "\n";
        var bytes = Encoding.ASCII.GetBytes(text);
        if (bytes.Length > MaximumBytes) throw new ArgumentException("Restricted Kerberos configuration is too large.");
        return bytes;
    }
    internal static void VerifyInherited(LdapWorkerStart profile)
    {
        if (profile.RestrictedConfiguration is not { } configuration) return;
        if (Environment.GetEnvironmentVariable("KRB5_CONFIG") != "/proc/self/fd/4" ||
            Environment.GetEnvironmentVariable("GSS_MECH_CONFIG") != "/proc/self/fd/5")
            throw new InvalidDataException("Restricted worker configuration was not installed before exec.");
        var expected = configuration.Generate(profile.Host);
        using var config = new SafeFileHandle((IntPtr)4, ownsHandle: false);
        using var mechanisms = new SafeFileHandle((IntPtr)5, ownsHandle: false);
        if (RandomAccess.GetLength(config) != expected.Length || RandomAccess.GetLength(mechanisms) != 0)
            throw new InvalidDataException("Inherited worker configuration has an unexpected size.");
        var actual = new byte[expected.Length];
        var offset = 0;
        while (offset < actual.Length)
        {
            var read = RandomAccess.Read(config, actual.AsSpan(offset), offset); // pread; preserve inherited offsets
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        if (!actual.AsSpan().SequenceEqual(expected)) throw new InvalidDataException("Inherited worker configuration differs from its recipe.");
    }
}
