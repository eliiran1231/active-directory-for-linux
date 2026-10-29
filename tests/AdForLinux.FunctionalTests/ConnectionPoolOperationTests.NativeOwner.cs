using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class RecordingBindingApi : NativeLdapBindingBackend.IBindingApi
    {
        internal int Resolutions, Binds, Source = 7, FailBind;
        internal Action? AfterFirstBind;
        internal readonly List<int> Consumed = [];
        internal readonly List<string> Trace = [];
        private readonly Dictionary<IntPtr, int> identities = [];
        public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        {
            authority = IntPtr.Zero; if (cancelled(state) != 0) return 3;
            authority = (IntPtr)(++Resolutions + 100); identities.Add(authority, Source); Trace.Add("resolve"); return 0;
        }
        public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
            NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session)
        {
            session = IntPtr.Zero; if (cancelled(state) != 0) return 3;
            Consumed.Add(identities[authority.DangerousGetHandle()]);
            session = (IntPtr)(++Binds + 200); Trace.Add("bind");
            if (Binds == 1) AfterFirstBind?.Invoke();
            return Binds == FailBind ? 5 : 0;
        }
        public void CloseAuthority(ref IntPtr authority) { identities.Remove(authority); Trace.Add("authority-close"); authority = IntPtr.Zero; }
        public void CloseSession(ref IntPtr session) { Trace.Add("session-close"); session = IntPtr.Zero; }
    }
    private static LdapConnectionOptions NativeOwnerOptions() => new()
    { Host = "directory.invalid", Port = 389, UseSsl = false, AuthenticationType = AuthType.Negotiate, Signing = true, Sealing = true, Timeout = TimeSpan.FromSeconds(5) };

    [Fact]
    public void Native_operation_resolves_once_after_admission_and_releases_owner_after_final_lease()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        var api = new RecordingBindingApi(); api.AfterFirstBind = () => api.Source = 9;
        using (var operation = NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 2, api: api))
        {
            Assert.Equal(1, api.Resolutions); Assert.Equal(new[] { 7, 7 }, api.Consumed);
            operation.Sessions[0].Dispose(); operation.Sessions[0].Dispose();
            Assert.DoesNotContain("authority-close", api.Trace);
            operation.Sessions[1].Dispose();
            Assert.Equal(new[] { "session-close", "session-close", "authority-close" }, api.Trace.TakeLast(3));
        }
        Assert.Equal(1, api.Trace.Count(item => item == "authority-close"));
        using var next = NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 1, api: api);
        Assert.Equal(2, api.Resolutions); Assert.Equal(9, api.Consumed[^1]);
    }

    [Fact]
    public void Native_operation_second_bind_failure_rolls_back_resources_and_capacity_without_retry()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
        var api = new RecordingBindingApi { FailBind = 2 };
        Assert.Throws<NativeLdapBindingBackend.NativeFailureException>(() => NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 2, api: api));
        Assert.Equal(2, api.Binds); Assert.Equal(1, api.Resolutions);
        Assert.Equal(new[] { "session-close", "session-close", "authority-close" }, api.Trace.TakeLast(3));
        Assert.Equal(0, pool.Snapshot.Total);
        using var next = NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 2, api: api);
        Assert.Equal(4, api.Binds); Assert.Equal(2, api.Resolutions);
    }

    [Fact]
    public void Native_operation_impossible_admission_or_unsupported_profile_never_resolves()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
        var api = new RecordingBindingApi();
        Assert.Throws<InvalidOperationException>(() => NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 2, api: api));
        Assert.Throws<PlatformNotSupportedException>(() => NativeLdapOperation.Acquire(pool, NativeOwnerOptions(), 1, ReferralChasingOption.All, api: api));
        Assert.Equal(0, api.Resolutions); Assert.Empty(api.Trace);
        var error = Assert.Throws<InvalidOperationException>(() => NativeLdapBindingBackend.ResolveForBinding(NativeOwnerOptions(), ReferralChasingOption.None));
        Assert.Equal(OfflineTestGuard.Message, error.Message); // real API still refuses before native entry
    }
}
