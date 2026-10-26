using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

// Deliberately restricted policy, not a transparent copy of host krb5.conf.
// No raw fragments, includes, module entries, discovery or k5identity.
// The path is a recipe: private compiled legacy plugin paths still require review.
internal sealed record LdapWorkerKdcEndpoint(string Host, int Port)
{
    internal string HostSpec()
    {
        if (Port is < 1 or > 65535 || string.IsNullOrEmpty(Host) || Host.Length > 253 ||
            Host.Split('.').Any(label => label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("KDC endpoint requires an ASCII DNS/IPv4 host and valid port.");
        return Host + ":" + Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
internal sealed record LdapWorkerKerberosProfile(string DefaultRealm, string ServiceHost, string PrivatePluginDirectory,
    LdapWorkerKdcEndpoint? Kdc = null)
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
        if (Kdc is not null)
            text += "[realms]\n " + DefaultRealm + " = {\n  kdc = " + Kdc.HostSpec() + "\n }\n";
        var bytes = Encoding.ASCII.GetBytes(text);
        if (bytes.Length > MaximumBytes) throw new ArgumentException("Restricted Kerberos configuration is too large.");
        return bytes;
    }
    internal static void RequireProductionPolicy(LdapWorkerStart profile)
    {
        if (profile.CredentialSource is null || profile.RestrictedConfiguration is null)
            throw new PlatformNotSupportedException("Production workers require an explicit source and restricted configuration.");
        profile.CredentialSource.Validate();
        _ = profile.RestrictedConfiguration.Generate(profile.Host);
    }
    // Linux UAPI: duplicate first, then verify seals and read the same owned fd.
    // FUTURE_WRITE is insufficient: existing mappings could still mutate bytes.
    private static SafeFileHandle DuplicateSealed(int descriptor)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Sealed worker profiles require Linux.");
        var duplicate = Fcntl(descriptor, 1030 /* F_DUPFD_CLOEXEC */, 6);
        if (duplicate < 0) throw new InvalidDataException("Cannot own inherited worker configuration.");
        var handle = new SafeFileHandle((IntPtr)duplicate, ownsHandle: true);
        var seals = Fcntl(duplicate, 1034 /* F_GET_SEALS */, 0);
        if (seals < 0 || (seals & 15 /* SEAL | SHRINK | GROW | WRITE */) != 15)
        {
            handle.Dispose();
            throw new InvalidDataException("Inherited worker configuration is not fully sealed.");
        }
        return handle;
    }
    [DllImport("libc", EntryPoint = "fcntl", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Fcntl(int descriptor, int command, int argument);

    internal static void VerifyInherited(LdapWorkerStart profile)
    {
        if (profile.RestrictedConfiguration is not { } configuration) return;
        if (Environment.GetEnvironmentVariable("KRB5_CONFIG") != "/proc/self/fd/4" ||
            Environment.GetEnvironmentVariable("GSS_MECH_CONFIG") != "/proc/self/fd/5")
            throw new InvalidDataException("Restricted worker configuration was not installed before exec.");
        var expected = configuration.Generate(profile.Host);
        using var config = DuplicateSealed(4);
        using var mechanisms = DuplicateSealed(5);
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
