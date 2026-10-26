using System.DirectoryServices.Protocols;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices.Ldap;
using Microsoft.Win32.SafeHandles;

// Explicit isolated-lab modes only. Never selected by the offline demo runner or
// production host. This code consumes actual disposable lab credentials if run.
internal static class RealLabWorker
{
    private const string Bundle = "/bundle/lab-v1";
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(15);
    private static LdapWorkerStart Profile(int identity) => new("127.0.0.1", 10389, false, true, true, 2,
        TimeSpan.FromSeconds(5), new(LdapCredentialSourceKind.File, identity == 1 ? "/run/adfl/client-a.ccache" : "/run/adfl/client-b.ccache"),
        new("ADFL.TEST", "127.0.0.1", "/run/adfl/plugins", new("127.0.0.1", 10088)));

    private static int OpenManifestHandles()
    {
        var count = 0;
        foreach (var path in Directory.EnumerateFiles("/proc/self/fd"))
            try { if (File.ResolveLinkTarget(path, false)?.FullName == Bundle + "/manifest.json") count++; }
            catch (IOException) { } // the enumeration descriptor may already have closed
        return count;
    }
    internal static void DeploymentPreflight()
    {
        var initial = OpenManifestHandles();
        var deployment = LdapWorkerDeployment.Validate(Bundle);
        var retained = deployment.Retain();
        deployment.Dispose();
        if (OpenManifestHandles() != initial + 1) throw new InvalidOperationException("Retained deployment handle was lost.");
        retained.Dispose();
        if (OpenManifestHandles() != initial) throw new InvalidOperationException("Deployment handles were not released.");
        foreach (var kind in new[] { "digest", "extra", "symlink" })
        {
            var refused = false;
            try { using var invalid = LdapWorkerDeployment.Validate("/admission-reject/" + kind); }
            catch (InvalidDataException) { refused = true; }
            if (!refused) throw new InvalidOperationException("Invalid bundle was admitted.");
        }
    }

    internal static async Task<int> Parent()
    {
        using var workers = new NativeLdapWorkerPool(2);
        NativeLdapWorkerPool.WorkerLease? a = null, b = null;
        var initialManifestHandles = OpenManifestHandles();
        var stage = 10;
        try
        {
            using var deployment = LdapWorkerDeployment.Validate(Bundle);
            stage = 11;
            a = await workers.AcquireAsync(deployment, Profile(1), Budget);
            stage = 12;
            b = await workers.AcquireAsync(deployment, Profile(2), Budget);
            deployment.Dispose(); // admitted workers retain the bundle until confirmed exit
            if (OpenManifestHandles() != initialManifestHandles + 1)
                throw new InvalidOperationException("Worker admission did not retain deployment ownership.");
            var command = new LdapSearchCommand("", "(objectClass=*)", SearchScope.Base,
                ["supportedLDAPVersion"], TimeSpan.FromSeconds(5));
            foreach (var lease in new[] { a, b })
            {
                stage = 13;
                foreach (var session in lease.Client.Sessions)
                {
                    var result = LdapRequestDispatcher.Search(session, command);
                    if (result.Code != ResultCode.Success || result.Entries.Length != 1 ||
                        !result.Entries[0].Attributes.TryGetValue("supportedLDAPVersion", out var versions) ||
                        !versions.Any(value => value.AsSpan().SequenceEqual("3"u8)))
                        throw new InvalidDataException("Real lab rootDSE response was invalid.");
                }
                stage = 14;
                await using var cursor = await ((ILdapConversationTransport)lease.Client.Sessions[0])
                    .OpenSearchAsync(command, 0, default);
                var entries = 0;
                while (true)
                {
                    var item = await cursor.ReadAsync(TimeSpan.FromSeconds(5), default);
                    if (item is LdapSearchEvent.Entry) entries++;
                    else if (item is LdapSearchEvent.PageEnd end)
                    {
                        if (end.HasMore || end.Result.Code != ResultCode.Success || entries != 1)
                            throw new InvalidDataException("Real lab cursor completion was invalid.");
                        break;
                    }
                    else throw new InvalidDataException("Unexpected real lab rootDSE reference.");
                }
            }
            stage = 15;
            a.Dispose(); b.Dispose();
            await Task.WhenAll(a.Cleanup, b.Cleanup).WaitAsync(Budget);
            if (workers.Snapshot.Tracked != 0 || OpenManifestHandles() != initialManifestHandles)
                throw new InvalidOperationException("Real lab workers or deployment were not released.");
            Console.WriteLine("PASS: real isolated supervised workers verified identities/protection before publication, paired rootDSE reads and cursors, and confirmed process cleanup.");
            return 0;
        }
        catch (Exception error)
        {
            // Fixed numeric status only; do not export native/runtime diagnostics.
            return stage + (error is TimeoutException ? 50 : error is PlatformNotSupportedException ? 100 : error is IOException ? 150 : 0);
        }
        finally
        {
            a?.Dispose(); b?.Dispose(); workers.Dispose();
            var cleanup = new[] { a, b }.Where(value => value is not null).Select(value => value!.Cleanup);
            try { await Task.WhenAll(cleanup).WaitAsync(Budget); }
            catch { Console.Error.WriteLine("Real lab worker cleanup remains unconfirmed."); }
        }
    }

    internal static async Task<int> Child()
    {

        if (Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") != "0") return 2;
        using var deployment = LdapWorkerDeployment.Validate(Bundle);
        using var supervisor = new WorkerNative(deployment.CreateLaunch().SupervisorLibrary);
        if (supervisor.SendIdentity(3) != 0) return 3;

        using var socket = new Socket(new SafeSocketHandle((IntPtr)3, ownsHandle: true));
        using var channel = new NetworkStream(socket, ownsSocket: false);
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        try
        {
            // Host verifies sealed inherited configuration BEFORE invoking factory.
            await LdapWorkerHost.RunAsync(channel, start =>
            {

                LdapWorkerKerberosProfile.RequireProductionPolicy(start);
                var identity = start == Profile(1) ? 1u : start == Profile(2) ? 2u : 0u;
                if (identity == 0) throw new InvalidDataException("Unexpected isolated lab recipe.");
                // Retained until process exit: private native libraries own static
                // state. No recording operations and no earlier backend loading.

                var library = NativeLibrary.Load(deployment.NativeBridgePath);
                NativeLibrary.SetDllImportResolver(typeof(NativeLdapBindingBackend).Assembly,
                    (name, _, _) => name == "adfl_native" ? library : IntPtr.Zero);
                var api = new LabApi(library, identity);
                var options = new LdapConnectionOptions { Host = start.Host, Port = start.Port, UseSsl = start.UseSsl,
                    AuthenticationType = AuthType.Negotiate, Signing = start.Signing, Sealing = start.Sealing, Timeout = start.Timeout };

                var owner = NativeLdapOperation.Acquire(pool, options, start.SessionCount, api: api, source: start.CredentialSource);
                try { return new LdapWorkerResources(owner, owner.Sessions.Select(session => session.ExecuteTransport(value => value)).ToArray()); }
                catch { owner.Dispose(); throw; }
            });
            return 0;
        }
        catch { return 5; }
    }

    private sealed class LabApi : NativeLdapBindingBackend.ISourceBindingApi
    {
        private readonly ResolveFromCall resolve;
        private readonly BindCall bind;
        private readonly CloseCall closeAuthority, closeSession;
        private readonly VerifyCall verify;
        private readonly uint identity;
        internal LabApi(IntPtr library, uint identity)
        {
            this.identity = identity;
            T Get<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            resolve = Get<ResolveFromCall>("adfl_lab_resolve_from"); bind = Get<BindCall>("adfl_authority_bind");
            closeAuthority = Get<CloseCall>("adfl_authority_close"); closeSession = Get<CloseCall>("adfl_session_close");
            verify = Get<VerifyCall>("adfl_lab_verify");
        }
        public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled,
            IntPtr state, out IntPtr authority) { authority = IntPtr.Zero; return 1; }
        public int ResolveFrom(ref NativeLdapBindingBackend.Profile profile, ref NativeLdapBindingBackend.CredentialSource source,
            NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        { NativeLdapBindingBackend.EnsureAbi(); return resolve(ref profile, ref source, cancelled, state, out authority); }
        public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
            NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session)
        {
            NativeLdapBindingBackend.EnsureAbi();
            var status = bind(authority, ref profile, cancelled, state, out session);
            try
            {
                if (status == 0) status = verify(session, identity);
                if (status != 0 && session != IntPtr.Zero) closeSession(ref session);
                return status;
            }
            catch { if (session != IntPtr.Zero) closeSession(ref session); throw; }
        }
        public void CloseAuthority(ref IntPtr authority) => closeAuthority(ref authority);
        public void CloseSession(ref IntPtr session) => closeSession(ref session);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ResolveFromCall(ref NativeLdapBindingBackend.Profile profile,
            ref NativeLdapBindingBackend.CredentialSource source, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindCall(NativeLdapBindingBackend.AuthorityHandle authority,
            ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void CloseCall(ref IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int VerifyCall(IntPtr session, uint identity);
    }
}
