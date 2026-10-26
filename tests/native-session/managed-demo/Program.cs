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
var open = Marshal.GetDelegateForFunctionPointer<Open>(NativeLibrary.GetExport(library, "adfl_test_open"));
var count = Marshal.GetDelegateForFunctionPointer<Count>(NativeLibrary.GetExport(library, "adfl_test_count"));
using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
LdapConnectionProvider.Session[] Acquire(LdapConnectionOptions options, int amount,
    ReferralChasingOption referrals, bool fresh, long minimum)
    => pool.AcquireBatch(LdapConnectionProvider.ConnectionKey.Create(options, referrals), amount, () =>
    {
        if (!NativeLdapBindingBackend.CanRepresentBinding(options, referrals))
            throw new InvalidOperationException("Facade profile is not representable by the native binding seam.");
        var profile = NativeLdapBindingBackend.Profile.From(options);
        profile.Referrals = (uint)referrals;
        if (open(ref profile, out var pointer) != 0 || pointer == IntPtr.Zero) throw new InvalidOperationException("Recording adapter failed to open.");
        var native = new NativeLdapBindingBackend.BoundSession(new NativeLdapBindingBackend.SessionHandle(pointer), options.Timeout);
        return new BoundLdapSession(native, native, options, new LdapAuthenticationSource(options), referrals);
    }, reusable: false).Select(lease => new LdapConnectionProvider.Session(lease)).ToArray();
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
// Resolver registration is process-lifetime; do not unload its library while
// SafeHandle finalizers or the runtime may retain function pointers.
[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Open(ref NativeLdapBindingBackend.Profile profile, out IntPtr session);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Count(int kind);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Configure(int scenario);
