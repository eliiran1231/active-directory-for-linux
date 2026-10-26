using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using AdForLinux.DirectoryServices.AccountManagement;

if (!OfflineTestGuard.Enabled) throw new InvalidOperationException("Run with the permanent offline guard enabled.");
if (args.Length != 1 || !Path.IsPathFullyQualified(args[0])) throw new ArgumentException("Supply the recording test library's absolute path.");
var library = NativeLibrary.Load(args[0]);
// Resolve only this assembly's owned native ABI to the explicitly built recording
// test library. This does not change credential environment or system library policy.
NativeLibrary.SetDllImportResolver(typeof(NativeLdapBindingBackend).Assembly,
    (name, _, _) => name == "adfl_native" ? library : IntPtr.Zero);
var bindingApi = new RecordingBindingApi(library);
var count = Marshal.GetDelegateForFunctionPointer<Count>(NativeLibrary.GetExport(library, "adfl_test_count"));
using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
LdapConnectionProvider.Session[] Acquire(LdapConnectionOptions options, int amount,
    ReferralChasingOption referrals, bool fresh, long minimum)
    => NativeLdapOperation.Acquire(pool, options, amount, referrals, api: bindingApi).Sessions.ToArray();

using var entry = new DirectoryEntry("LDAP://directory.invalid/DC=example", null, null, AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing);
entry.Options.Referral = ReferralChasingOption.None;
entry.OperationSessionFactory = Acquire;
if (entry.Options.GetCurrentServerName() != "observed-dc.invalid") throw new InvalidOperationException("DirectoryServices roundtrip failed.");
using var context = new PrincipalContext(ContextType.Domain, "directory.invalid", null, ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing);
context.TransportSessionFactory = options => Acquire(options, 1, ReferralChasingOption.None, false, 0)[0];
if (context.ConnectedServer != "observed-dc.invalid" || context.DefaultNamingContext != "DC=example")
    throw new InvalidOperationException("AccountManagement roundtrip failed.");
for (var kind = 0; kind < 4; kind++)
    if (count(kind) != 3) throw new InvalidOperationException("Native dispatch/result/session/authority ownership was not balanced.");
Console.WriteLine("PASS: both public facades -> common lease -> managed native ABI -> actual C dispatcher -> recording dependencies -> owned managed results.");
Console.WriteLine("Three requests, messages, sessions and authorities balanced. No credentials, sockets or authentication used.");
// Exercise the actual conversation adapter and ABI, not a parallel managed fake.
var configure = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_configure"));
if (configure(1) != 0) throw new InvalidOperationException("Recording scenario change rejected.");
LdapConnectionProvider.Session AcquireConversation() => Acquire(entry.BuildOptions(), 1, ReferralChasingOption.None, false, 0)[0];
var events = new List<LdapSearchEvent>();
await foreach (var item in LdapConversation.Search(AcquireConversation,
    new LdapSearchCommand("", "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Subtree,
        ["binary"], TimeSpan.FromSeconds(10)), pageSize: 2)) events.Add(item);
if (events.Count != 6 || events[0] is not LdapSearchEvent.Entry first || events[1] is not LdapSearchEvent.Reference ||
    events[2] is not LdapSearchEvent.PageEnd { HasMore: true } || events[3] is not LdapSearchEvent.Entry second ||
    events[4] is not LdapSearchEvent.Reference || events[5] is not LdapSearchEvent.PageEnd { HasMore: false } ||
    first.Value.DistinguishedName != "CN=first" || second.Value.DistinguishedName != "CN=second" ||
    !first.Value.Attributes["binary"][0].SequenceEqual(new byte[] { 0, 255, 65 }))
    throw new InvalidOperationException("Native ordered/paged conversation failed.");
var outcome = await LdapConversation.Modify(AcquireConversation, new("CN=example",
    [new("description", System.DirectoryServices.Protocols.DirectoryAttributeOperation.Replace, [Array.Empty<byte>()]),
     new("other", System.DirectoryServices.Protocols.DirectoryAttributeOperation.Delete, [])], TimeSpan.FromSeconds(10), []));
if (outcome.Disposition != LdapWriteDisposition.Completed || outcome.Result is not { Code: System.DirectoryServices.Protocols.ResultCode.UnwillingToPerform } result ||
    result.MatchedDn != "DC=example" || result.Diagnostic != "synthetic complete result" || result.Referrals.Length != 1 ||
    result.Controls.Length != 1 || result.Controls[0].Oid != "1.2.4")
    throw new InvalidOperationException("Native definitive write-error envelope was lost.");
if (count(1) != 5 || count(2) != 5 || count(3) != 10 || count(4) != 2 || count(5) != 1 || count(6) != 1)
    throw new InvalidOperationException("Native conversation ownership/submission counters were not balanced.");
Console.WriteLine("PASS: native two-page streaming, opaque cookie continuation and complete modify error through the production managed/C adapters.");
Console.WriteLine("One lease across pages; one write submission; owned binary results. Recording dependencies only.");
// Same-target search/schema admission consumes one resolved resource even when
// the synthetic source changes between binds. Next operation resolves afresh.
var identity = Marshal.GetDelegateForFunctionPointer<SetIdentity>(NativeLibrary.GetExport(library, "adfl_test_set_identity"));
var failBind = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_fail_nth_bind"));
if (identity(7, 7) != 0) throw new InvalidOperationException("Recording identity setup failed.");
var selectedBefore = count(7); var acquiredBefore = count(8); var bindsBefore = count(9); var pairBinds = 0;
bindingApi.AfterBind = () => { if (++pairBinds == 1 && identity(9, 7) != 0) throw new InvalidOperationException("Source transition failed."); };
using (var pair = NativeLdapOperation.Acquire(pool, entry.BuildOptions(), 2, api: bindingApi))
{
    if (pair.Sessions.Count != 2 || count(7) != selectedBefore + 1 || count(8) != acquiredBefore + 1 || count(9) != bindsBefore + 2)
        throw new InvalidOperationException("Search/schema pair did not share one resolved authority.");
}
bindingApi.AfterBind = null;
if (identity(9, 9) != 0) throw new InvalidOperationException("Next source setup failed.");
using (var next = NativeLdapOperation.Acquire(pool, entry.BuildOptions(), 1, api: bindingApi)) { }
var closesBefore = count(1); var freesBefore = count(2);
if (failBind(2) != 0) throw new InvalidOperationException("Bind failure setup failed.");
var failed = false;
try { using var rejected = NativeLdapOperation.Acquire(pool, entry.BuildOptions(), 2, api: bindingApi); }
catch (InvalidOperationException) { failed = true; }
if (!failed || pool.Snapshot.Total != 0 || count(1) != closesBefore + 2 || count(2) != freesBefore + 1)
    throw new InvalidOperationException("Failed paired admission did not roll back resources/capacity.");
selectedBefore = count(7);
try { using var impossible = NativeLdapOperation.Acquire(pool, entry.BuildOptions(), 3, api: bindingApi); }
catch (InvalidOperationException) { }
if (count(7) != selectedBefore) throw new InvalidOperationException("Impossible admission resolved credentials.");
Console.WriteLine("PASS: managed operation owner -> atomic admission -> one target resolution -> paired native binds; source replacement and failed-bind rollback verified.");
// Public buffered searches drain their cursor before asking schema questions on
// that same lease. This fixture intentionally omits schemaNamingContext: these
// assertions cover ownership/routing and fallback, not AD schema fidelity.
var bufferedSelected = count(7); var bufferedCloses = count(1); var bufferedFrees = count(2);
var bufferedPages = count(4); var bufferedResults = count(3);
using (var searcher = new DirectorySearcher(entry)
{
    Filter = "(objectClass=*)", PageSize = 2, CacheResults = true, Asynchronous = false,
    ReferralChasing = ReferralChasingOption.None, ClientTimeout = TimeSpan.FromSeconds(10)
})
{
    using var results = searcher.FindAll();
    if (results.Count != 2 || !results[0].Path.EndsWith("/CN=first", StringComparison.Ordinal) ||
        !results[1].Path.EndsWith("/CN=second", StringComparison.Ordinal))
        throw new InvalidOperationException("Public buffered FindAll did not preserve native pages/results.");
    searcher.PageSize = 0;
    var one = searcher.FindOne();
    if (one is null || !one.Path.EndsWith("/CN=first", StringComparison.Ordinal))
        throw new InvalidOperationException("Public buffered FindOne did not preserve native result.");
}
if (pool.Snapshot.Total != 0 || count(7) != bufferedSelected + 3 ||
    count(1) != bufferedCloses + 3 || count(2) != bufferedFrees + 3 ||
    count(4) != bufferedPages + 3 || count(3) != bufferedResults + 12)
    throw new InvalidOperationException($"Public buffered resources unbalanced: resolves={count(7)-bufferedSelected}, closes={count(1)-bufferedCloses}, frees={count(2)-bufferedFrees}, pages={count(4)-bufferedPages}, results={count(3)-bufferedResults}.");
Console.WriteLine("PASS: public buffered DirectorySearcher FindAll/FindOne -> actual native cursor; schema fallback after cursor close; operation resources balanced.");
// Resolver registration is process-lifetime; do not unload its library while
// SafeHandle finalizers or the runtime may retain function pointers.
[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Count(int kind);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Configure(int scenario);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int SetIdentity(int source, int expected);

// Only this isolated demo supplies recording operations. The system binding API
// retains its permanent live-access guard and the native pre-auth gate remains0.
sealed class RecordingBindingApi : NativeLdapBindingBackend.IBindingApi
{
    private readonly ResolveCall resolve;
    private readonly BindCall bind;
    private readonly CloseCall closeAuthority, closeSession;
    internal Action? AfterBind;
    internal RecordingBindingApi(IntPtr library)
    {
        resolve = Marshal.GetDelegateForFunctionPointer<ResolveCall>(NativeLibrary.GetExport(library, "adfl_test_resolve"));
        bind = Marshal.GetDelegateForFunctionPointer<BindCall>(NativeLibrary.GetExport(library, "adfl_authority_bind"));
        closeAuthority = Marshal.GetDelegateForFunctionPointer<CloseCall>(NativeLibrary.GetExport(library, "adfl_authority_close"));
        closeSession = Marshal.GetDelegateForFunctionPointer<CloseCall>(NativeLibrary.GetExport(library, "adfl_session_close"));
    }
    public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        => resolve(ref profile, cancelled, state, out authority);
    public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
        NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session)
    {
        var result = bind(authority, ref profile, cancelled, state, out session);
        try { if (result == 0) AfterBind?.Invoke(); return result; }
        catch { if (session != IntPtr.Zero) closeSession(ref session); throw; }
    }
    public void CloseAuthority(ref IntPtr authority) => closeAuthority(ref authority);
    public void CloseSession(ref IntPtr session) => closeSession(ref session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ResolveCall(ref NativeLdapBindingBackend.Profile profile,
        NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindCall(NativeLdapBindingBackend.AuthorityHandle authority,
        ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void CloseCall(ref IntPtr value);
}
