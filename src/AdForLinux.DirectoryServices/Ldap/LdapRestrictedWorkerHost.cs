using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;

namespace AdForLinux.DirectoryServices.Ldap;

// Called only by the isolated executable after deployment/caller admission.
// Generic system/native resolve paths remain disabled; this factory has no
// environment enable switch and accepts only a verified source-only composition.
internal static class LdapRestrictedWorkerHost
{
    internal static LdapWorkerResources Create(VerifiedDeployment deployment, LdapWorkerStart start)
    {
        OfflineTestGuard.RequireLiveAccess();
        if (Environment.GetEnvironmentVariable("LDAPNOINIT") != "1")
            throw new PlatformNotSupportedException("Restricted workers must disable ambient OpenLDAP configuration before library load.");
        LdapWorkerKerberosProfile.RequireProductionPolicy(start);
        LdapWorkerKerberosProfile.VerifyInherited(start);
        deployment.RequireRestrictedComposition();
        var options = new LdapConnectionOptions
        {
            Host = start.Host, Port = start.Port, UseSsl = false, AuthenticationType = AuthType.Negotiate,
            Signing = start.Signing, Sealing = start.Sealing, Timeout = start.Timeout
        };
        if (!NativeLdapBindingBackend.CanRepresentBinding(options, ReferralChasingOption.None))
            throw new PlatformNotSupportedException("Restricted worker cannot represent the complete recipe.");
        // One isolated host loads one admitted bridge. Keep it loaded until process
        // exit: LDAP/Cyrus/GSS own static state. No parent loader is modified.
        var library = NativeLibrary.Load(deployment.NativeBridgePath);
        NativeLibrary.SetDllImportResolver(typeof(NativeLdapBindingBackend).Assembly,
            (name, _, _) => name == "adfl_native" ? library : IntPtr.Zero);
        var api = new SourceApi(library);
        NativeLdapBindingBackend.EnsureAbi();
        var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        try
        {
            var operation = NativeLdapOperation.Acquire(pool, options, start.SessionCount, api: api, source: start.CredentialSource);
            try { return new LdapWorkerResources(new Owner(operation, pool), operation.Sessions.Select(session => session.ExecuteTransport(value => value)).ToArray()); }
            catch { operation.Dispose(); throw; }
        }
        catch { pool.Dispose(); throw; }
    }
    private sealed class Owner(NativeLdapOperation operation, IDisposable pool) : IDisposable
    {
        public void Dispose() { try { operation.Dispose(); } finally { pool.Dispose(); } }
    }
    private sealed class SourceApi : NativeLdapBindingBackend.ISourceBindingApi
    {
        private readonly ResolveFromCall resolve;
        private readonly BindCall bind;
        private readonly CloseCall closeAuthority, closeSession;
        internal SourceApi(IntPtr library)
        {
            T Get<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            resolve = Get<ResolveFromCall>("adfl_restricted_authority_resolve_from");
            bind = Get<BindCall>("adfl_restricted_authority_bind");
            closeAuthority = Get<CloseCall>("adfl_authority_close"); closeSession = Get<CloseCall>("adfl_session_close");
        }
        public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        { authority = IntPtr.Zero; return 1; }
        public int ResolveFrom(ref NativeLdapBindingBackend.Profile profile, ref NativeLdapBindingBackend.CredentialSource source,
            NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        { OfflineTestGuard.RequireLiveAccess(); return resolve(ref profile, ref source, cancelled, state, out authority); }
        public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
            NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session)
        { OfflineTestGuard.RequireLiveAccess(); return bind(authority, ref profile, cancelled, state, out session); }
        public void CloseAuthority(ref IntPtr value) => closeAuthority(ref value);
        public void CloseSession(ref IntPtr value) => closeSession(ref value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ResolveFromCall(ref NativeLdapBindingBackend.Profile profile,
            ref NativeLdapBindingBackend.CredentialSource source, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindCall(NativeLdapBindingBackend.AuthorityHandle authority,
            ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void CloseCall(ref IntPtr value);
    }
}
