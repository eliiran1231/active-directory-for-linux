using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Ownership adapter for the experimental OpenLDAP binding bridge. This is a
/// separate transport resource, never a fabricated Protocols LdapConnection.
/// The facade must not select it until authority enforcement and complete request semantics are established.
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

    // This flag is deliberately independent of native library availability. An
    // implemented search bridge does not establish pre-authentication authority enforcement.
    internal static bool SupportsFacadeRequests => false;

    // Dependency injection is explicit and local to the owner. The real API keeps
    // its live-access guards; no process/global switch can change those checks.
    internal interface IBindingApi
    {
        int Resolve(ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr authority);
        int Bind(AuthorityHandle authority, ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr session);
        void CloseAuthority(ref IntPtr authority);
        void CloseSession(ref IntPtr session);
    }
    internal interface ISourceBindingApi : IBindingApi
    {
        int ResolveFrom(ref Profile profile, ref CredentialSource source, Cancelled cancelled, IntPtr state, out IntPtr authority);
    }
    private sealed class SystemBindingApi : ISourceBindingApi
    {
        internal static readonly SystemBindingApi Instance = new();
        public int Resolve(ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr authority)
        { OfflineTestGuard.RequireLiveAccess(); EnsureAbi(); return NativeResolve(ref profile, cancelled, state, out authority); }
        public int ResolveFrom(ref Profile profile, ref CredentialSource source, Cancelled cancelled, IntPtr state, out IntPtr authority)
        { OfflineTestGuard.RequireLiveAccess(); EnsureAbi(); return NativeResolveFrom(ref profile, ref source, cancelled, state, out authority); }
        public int Bind(AuthorityHandle authority, ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr session)
        { OfflineTestGuard.RequireLiveAccess(); EnsureAbi(); return NativeBind(authority, ref profile, cancelled, state, out session); }
        public void CloseAuthority(ref IntPtr authority) => NativeAuthorityClose(ref authority);
        public void CloseSession(ref IntPtr session) => NativeSessionClose(ref session);
    }

    internal static Authority ResolveForBinding(LdapConnectionOptions options,
        ReferralChasingOption referrals, CancellationToken cancellationToken = default, LdapCredentialSource? source = null)
        => ResolveForBinding(options, referrals, SystemBindingApi.Instance, cancellationToken, source);

    internal static Authority ResolveForBinding(LdapConnectionOptions options,
        ReferralChasingOption referrals, IBindingApi api, CancellationToken cancellationToken = default, LdapCredentialSource? source = null)
    {
        ArgumentNullException.ThrowIfNull(api);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CanRepresentBinding(options, referrals))
            throw new PlatformNotSupportedException("The native binding prototype cannot represent this complete authentication/transport/referral profile.");
        source?.Validate();
        if (source is not null && api is not ISourceBindingApi)
            throw new PlatformNotSupportedException("The binding API cannot consume an explicit credential source.");
        var snapshot = options.Clone();
        var profile = Profile.From(snapshot);
        Cancelled check = _ => cancellationToken.IsCancellationRequested ? 1 : 0;
        IntPtr handle;
        int status;
        if (source is null) status = api.Resolve(ref profile, check, IntPtr.Zero, out handle);
        else
        {
            var nativeSource = new CredentialSource { Kind = (uint)source.Kind, AbsolutePath = source.AbsolutePath };
            status = ((ISourceBindingApi)api).ResolveFrom(ref profile, ref nativeSource, check, IntPtr.Zero, out handle);
        }
        if (status != 0 || handle == IntPtr.Zero)
        {
            if (handle != IntPtr.Zero) api.CloseAuthority(ref handle);
            if (status != 0) Throw(status, cancellationToken);
            throw new InvalidOperationException("Native resolution returned no authority.");
        }
        return new Authority(new AuthorityHandle(handle, api), snapshot, api);
    }

    internal sealed class Authority(AuthorityHandle handle, LdapConnectionOptions profile, IBindingApi api) : IDisposable
    {
        // Every bind consumes the same selected resource/profile/API. This is
        // not an assertion that mutable credential-cache contents were snapshotted.
        internal BoundSession Bind(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(handle.IsClosed, this);
            cancellationToken.ThrowIfCancellationRequested();
            var native = Profile.From(profile);
            Cancelled check = _ => cancellationToken.IsCancellationRequested ? 1 : 0;
            var status = api.Bind(handle, ref native, check, IntPtr.Zero, out var session);
            if (status != 0 || session == IntPtr.Zero)
            {
                if (session != IntPtr.Zero) api.CloseSession(ref session);
                if (status != 0) Throw(status, cancellationToken);
                throw new InvalidOperationException("Native bind returned no session.");
            }
            return new BoundSession(new SessionHandle(session, api), profile.Timeout);
        }
        public void Dispose() => handle.Dispose();
    }

    internal sealed class AuthorityHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly IBindingApi api;
        internal AuthorityHandle(IntPtr value, IBindingApi? api = null) : base(true)
        { this.api = api ?? SystemBindingApi.Instance; SetHandle(value); }
        protected override bool ReleaseHandle() { api.CloseAuthority(ref handle); return true; }
    }
    internal sealed class SessionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly IBindingApi api;
        internal SessionHandle(IntPtr value, IBindingApi? api = null) : base(true)
        { this.api = api ?? SystemBindingApi.Instance; SetHandle(value); }
        protected override bool ReleaseHandle() { api.CloseSession(ref handle); return true; }
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
    internal delegate int Cancelled(IntPtr state);
    private const string Library = "adfl_native";
    [StructLayout(LayoutKind.Sequential)]
    internal struct CredentialSource
    {
        public uint Kind;
        [MarshalAs(UnmanagedType.LPUTF8Str)] public string AbsolutePath;
    }
    [DllImport(Library, EntryPoint = "adfl_authority_resolve_from", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeResolveFrom(ref Profile profile, ref CredentialSource source, Cancelled cancelled, IntPtr state, out IntPtr authority);
    [DllImport(Library, EntryPoint = "adfl_authority_resolve", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeResolve(ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr authority);
    [DllImport(Library, EntryPoint = "adfl_authority_bind", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeBind(AuthorityHandle authority, ref Profile profile, Cancelled cancelled, IntPtr state, out IntPtr session);
    [DllImport(Library, EntryPoint = "adfl_authority_close", CallingConvention = CallingConvention.Cdecl)]
    private static extern void NativeAuthorityClose(ref IntPtr authority);
    [DllImport(Library, EntryPoint = "adfl_session_close", CallingConvention = CallingConvention.Cdecl)]
    private static extern void NativeSessionClose(ref IntPtr session);
}
