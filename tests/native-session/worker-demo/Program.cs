using System.Diagnostics;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using System.DirectoryServices.Protocols;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Microsoft.Win32.SafeHandles;

if (args.FirstOrDefault() == "--child") return await Child(args);
if (!OfflineTestGuard.Enabled || args.Length != 4) throw new InvalidOperationException("Use the offline worker runner with dotnet, supervisor, recording bridge and production host paths.");
var executable = Path.GetFullPath(args[0]);
var supervisorPath = Path.GetFullPath(args[1]);
var bridgePath = Path.GetFullPath(args[2]);
var productionHost = Path.GetFullPath(args[3]);
var assembly = typeof(Program).Assembly.Location;
var profile = new LdapWorkerStart("directory.invalid", 389, false, true, true, 2, TimeSpan.FromSeconds(5));
WorkerLaunch Launch(string mode) => new(executable, [assembly, "--child", supervisorPath, bridgePath, mode], supervisorPath);
var read = new LdapSearchCommand("", "(objectClass=*)", SearchScope.Base, ["dnsHostName"], TimeSpan.FromSeconds(2));
var modify = new LdapModifyCommand("CN=example", [new("description", DirectoryAttributeOperation.Replace, [Array.Empty<byte>()]), new("other", DirectoryAttributeOperation.Delete, [])], TimeSpan.FromSeconds(2), []);
using var workers = new NativeLdapWorkerPool(1);
async Task Empty()
{
    var stop = Stopwatch.StartNew();
    while (workers.Snapshot.Tracked != 0 && stop.Elapsed < TimeSpan.FromSeconds(5)) await Task.Delay(10);
    if (workers.Snapshot.Tracked != 0) throw new InvalidOperationException("Known worker was not reaped; capacity remained occupied.");
}

try
{
using (var lease = await workers.AcquireAsync(Launch("normal"), profile, TimeSpan.FromSeconds(5)))
{
    var first = LdapRequestDispatcher.Search(lease.Client.Sessions[0], read);
    if (first.Entries.Length != 1) throw new InvalidOperationException("Worker lost buffered result.");
    var transport = (ILdapConversationTransport)lease.Client.Sessions[0];
    await using (var cursor = await transport.OpenSearchAsync(read with { Scope = SearchScope.Subtree, Attributes = ["binary"] }, 2, default))
    {
        var pages = 0; var entries = 0;
        while (true)
        {
            var item = await cursor.ReadAsync(TimeSpan.FromSeconds(2), default);
            if (item is LdapSearchEvent.Entry entry)
            {
                entries++;
                if (!entry.Value.Attributes["BINARY"][0].SequenceEqual(new byte[] { 0, 255, 65 })) throw new InvalidOperationException("IPC changed binary values/comparer.");
            }
            if (item is LdapSearchEvent.PageEnd page)
            {
                pages++;
                if (!page.HasMore) break;
                await cursor.NextPageAsync(TimeSpan.FromSeconds(2), default);
            }
        }
        if (pages != 2 || entries != 2) throw new InvalidOperationException("Worker paging state was lost.");
    }
    // Cursor closure does not close the worker or its paired schema session.
    if (LdapRequestDispatcher.Search(lease.Client.Sessions[1], read).Entries.Length != 1) throw new InvalidOperationException("Dependent schema session was lost.");
    var submitted = new LdapSubmission();
    var result = await ((ILdapMutationTransport)lease.Client.Sessions[0]).MutateAsync(modify, submitted, default);
    if (!submitted.Started || result.Code != ResultCode.UnwillingToPerform) throw new InvalidOperationException("Complete native rejection lost across IPC.");
}
await Empty();
Console.WriteLine("PASS: isolated actual native dispatcher serves paired sessions, pages, binary results and complete mutation responses over bounded IPC.");

foreach (var (mode, disposition) in new[] { ("before-write", LdapWriteDisposition.NotSent), ("after-write", LdapWriteDisposition.Indeterminate) })
{
    var lease = await workers.AcquireAsync(Launch(mode), profile with { SessionCount = 1 }, TimeSpan.FromSeconds(5));
    using var sessions = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(1, 1, startTimer: false);
    var options = new LdapConnectionOptions { Host = "directory.invalid", UseSsl = false, Port = 389, AuthenticationType = AuthType.Negotiate, Signing = true, Sealing = true };
    LdapConnectionProvider.Session Acquire() => new(sessions.Acquire(LdapConnectionProvider.ConnectionKey.Create(options, ReferralChasingOption.None),
        () => new BoundLdapSession(lease.Client.Sessions[0], lease, options, new LdapAuthenticationSource(options), ReferralChasingOption.None), reusable: false));
    var elapsed = Stopwatch.StartNew();
    var outcome = await LdapConversation.Mutate(Acquire, modify with { Timeout = TimeSpan.FromMilliseconds(300) });
    if (outcome.Disposition != disposition || elapsed.Elapsed > TimeSpan.FromSeconds(3)) throw new InvalidOperationException("Blocked native write escaped parent deadline/outcome policy.");
    await lease.Cleanup.WaitAsync(TimeSpan.FromSeconds(5)); await Empty();
}
Console.WriteLine("PASS: actual C dependencies blocked before/after execution authorization yield NotSent/Indeterminate without replay; parent returns and pidfd cleanup reaps worker.");

using (var lease = await workers.AcquireAsync(Launch("blocked-read"), profile with { SessionCount = 1 }, TimeSpan.FromSeconds(5)))
{
    var elapsed = Stopwatch.StartNew();
    try { LdapRequestDispatcher.Search(lease.Client.Sessions[0], read with { Timeout = TimeSpan.FromMilliseconds(300) }); throw new InvalidOperationException("Blocked read returned."); }
    catch (TimeoutException) { }
    if (elapsed.Elapsed > TimeSpan.FromSeconds(3)) throw new InvalidOperationException("Native read held parent indefinitely.");
    await lease.Cleanup.WaitAsync(TimeSpan.FromSeconds(5));
}
await Empty();

// Startup timeout keeps its slot until the delayed, owned child identifies and is
// reaped. A second acquisition cannot spawn an unbounded replacement population.
try { using var late = await workers.AcquireAsync(Launch("late-identity"), profile, TimeSpan.FromMilliseconds(100)); throw new InvalidOperationException("Expected startup timeout."); }
catch (TimeoutException) { }
if (workers.Snapshot is not { Tracked: 1, Retiring: 1 }) throw new InvalidOperationException("Unreaped worker capacity was recycled.");
try { using var excess = await workers.AcquireAsync(Launch("normal"), profile, TimeSpan.FromMilliseconds(100)); throw new InvalidOperationException("Quarantined capacity admitted another worker."); }
catch (TimeoutException) { }
await Empty();
Console.WriteLine("PASS: pending startup/dying workers retain capacity until confirmed cleanup; no replacement storm.");

foreach (var mode in new[] { "malformed", "exit" })
{
    try { using var bad = await workers.AcquireAsync(Launch(mode), profile, TimeSpan.FromSeconds(3)); throw new InvalidOperationException("Invalid worker was admitted."); }
    catch (Exception error) when (error is not InvalidOperationException || error.Message != "Invalid worker was admitted.") { }
    await Empty();
}
try
{
    using var rejected = await workers.AcquireAsync(new WorkerLaunch(executable, [productionHost, supervisorPath], supervisorPath), profile, TimeSpan.FromSeconds(5));
    throw new InvalidOperationException("Production helper enabled authentication.");
}
catch (PlatformNotSupportedException) { }
await Empty();
Console.WriteLine("PASS: malformed/closed peers are retired; production helper refuses before authentication. No credentials, LDAP network connections or host configuration used.");
return 0;
}
finally
{
    workers.Dispose();
    await Empty();
}

static async Task<int> Child(string[] arguments)
{
    if (!OfflineTestGuard.Enabled || arguments.Length != 4) return 2;
    var mode = arguments[3];
    if (mode == "late-identity") await Task.Delay(700);
    using var native = new WorkerNative(arguments[1]);
    if (native.SendIdentity(3) != 0) return 3;
    using var socket = new Socket(new SafeSocketHandle((IntPtr)3, ownsHandle: true));
    using var channel = new NetworkStream(socket, ownsSocket: false);
    if (mode == "exit") return 0;
    if (mode == "malformed") { await channel.WriteAsync(new byte[] { 255, 255, 255, 127 }); await Task.Delay(5000); return 0; }
    var library = NativeLibrary.Load(arguments[2]);
    NativeLibrary.SetDllImportResolver(typeof(NativeLdapBindingBackend).Assembly, (name, _, _) => name == "adfl_native" ? library : IntPtr.Zero);
    var configure = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_configure"));
    var block = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_set_block"));
    if (configure(1) != 0 || block(mode switch { "blocked-read" => 1, "before-write" => 2, "after-write" => 3, _ => 0 }) != 0) return 4;
    var api = new RecordingBindingApi(library);
    using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
    try
    {
        await LdapWorkerHost.RunAsync(channel, start =>
        {
            var options = new LdapConnectionOptions { Host = start.Host, Port = start.Port, UseSsl = start.UseSsl,
                AuthenticationType = AuthType.Negotiate, Signing = start.Signing, Sealing = start.Sealing, Timeout = start.Timeout };
            var owner = NativeLdapOperation.Acquire(pool, options, start.SessionCount, api: api);
            return new LdapWorkerResources(owner, owner.Sessions.Select(session => session.ExecuteTransport(value => value)).ToArray());
        }, CancellationToken.None);
        return 0;
    }
    catch { return 5; }
}
[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Configure(int value);
