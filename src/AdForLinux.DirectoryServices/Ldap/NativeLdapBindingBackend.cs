using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Ownership adapter for the experimental OpenLDAP binding bridge. This is a
/// separate transport resource, never a fabricated Protocols LdapConnection.
/// The facade must not select it until request transport capability is implemented.
/// </summary>
internal static partial class NativeLdapBindingBackend
{
    internal static bool CanRepresentBinding(LdapConnectionOptions options, ReferralChasingOption referrals) =>
        OperatingSystem.IsLinux() && IsTargetSupported(options.Host) && options.AuthenticationType == AuthType.Negotiate &&
        string.IsNullOrEmpty(options.BindDn) && string.IsNullOrEmpty(options.BindPassword) &&
        referrals == ReferralChasingOption.None && !options.UseSsl && !options.UseStartTls &&
        !options.SkipCertificateCheck && (options.Signing || options.Sealing) &&
        options.Port is > 0 and <= 65535 && options.Timeout.TotalSeconds is >= 1 and <= 3600 &&
        options.Timeout.Ticks % TimeSpan.TicksPerSecond == 0;

    private static bool IsTargetSupported(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253) return false;
        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            foreach (var c in label)
                if (!char.IsAsciiLetterOrDigit(c) && c != '-') return false;
        }
        return true;
    }

    // This flag is deliberately independent of native library availability. A
    // implemented search bridge does not establish pre-authentication authority enforcement.
    internal static bool SupportsFacadeRequests => false;

    internal static Authority ResolveForBinding(LdapConnectionOptions options,
        ReferralChasingOption referrals, CancellationToken cancellationToken = default)
    {
        OfflineTestGuard.RequireLiveAccess();
        if (!CanRepresentBinding(options, referrals))
            throw new PlatformNotSupportedException("The native binding prototype cannot represent this complete authentication/transport/referral profile.");
        var snapshot = options.Clone();
        var profile = Profile.From(snapshot);
        Cancelled check = _ => cancellationToken.IsCancellationRequested ? 1 : 0;
        var status = NativeResolve(ref profile, check, IntPtr.Zero, out var handle);
        if (status != 0)
        {
            if (handle != IntPtr.Zero) NativeAuthorityClose(ref handle);
            Throw(status, cancellationToken);
        }
        return new Authority(new AuthorityHandle(handle), snapshot);
    }

    internal sealed class Authority(AuthorityHandle handle, LdapConnectionOptions profile) : IDisposable
    {
        // Each bind consumes this native resolved authority; replacement/parallel
        // binds do not reacquire ambient credentials. New operations resolve anew.
        internal BoundSession Bind(CancellationToken cancellationToken = default)
        {
            OfflineTestGuard.RequireLiveAccess();
            var native = Profile.From(profile);
            Cancelled check = _ => cancellationToken.IsCancellationRequested ? 1 : 0;
            var status = NativeBind(handle, ref native, check, IntPtr.Zero, out var session);
            if (status != 0)
            {
                if (session != IntPtr.Zero) NativeSessionClose(ref session);
                Throw(status, cancellationToken);
            }
            return new BoundSession(new SessionHandle(session), profile.Timeout);
        }
        public void Dispose() => handle.Dispose();
    }

    internal sealed class AuthorityHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal AuthorityHandle(IntPtr value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle() { NativeAuthorityClose(ref handle); return true; }
    }
    internal sealed class SessionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SessionHandle(IntPtr value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle() { NativeSessionClose(ref handle); return true; }
    }

    private static void Throw(int status, CancellationToken cancellationToken)
    {
        if (status == 3) throw new OperationCanceledException(cancellationToken);
        if (status == 13) throw new TimeoutException("Native LDAP request deadline expired; session retired without replay.");
        if (status == 1) throw new PlatformNotSupportedException("Native library composition or profile is unsupported; preserve the caller's profile in the existing fresh backend.");
        throw new InvalidOperationException($"Native authority/binding failed (status {status}); no retry was performed.");
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Profile
    {
        [MarshalAs(UnmanagedType.LPUTF8Str)] public string Host;
        public uint Port, TimeoutSeconds, Referrals, Tls, Signing, Sealing;
        internal static Profile From(LdapConnectionOptions options) => new()
        {
            Host = options.Host, Port = checked((uint)options.Port),
            TimeoutSeconds = checked((uint)options.Timeout.TotalSeconds),
            Signing = options.Signing ? 1u : 0u, Sealing = options.Sealing ? 1u : 0u,
        };
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Cancelled(IntPtr state);
    private const string Library = "adfl_native";
    [DllImport(Library, EntryPoint = "adfl_authority_resolve", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeResolve(ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr authority);
    [DllImport(Library, EntryPoint = "adfl_authority_bind", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeBind(AuthorityHandle authority, ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr session);
    [DllImport(Library, EntryPoint = "adfl_authority_close", CallingConvention = CallingConvention.Cdecl)]
    private static extern void NativeAuthorityClose(ref IntPtr authority);
    [DllImport(Library, EntryPoint = "adfl_session_close", CallingConvention = CallingConvention.Cdecl)]
    private static extern void NativeSessionClose(ref IntPtr session);
}
