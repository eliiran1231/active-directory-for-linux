using System.Diagnostics;
using System.Text;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using System.DirectoryServices.Protocols;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Microsoft.Win32.SafeHandles;

if (args is ["--real-lab-runtime-probe"])
{
    _ = System.Security.Cryptography.HMACSHA256.HashData(new byte[32], "runtime-fixture"u8);
    RealLabWorker.DeploymentPreflight();
    if (Directory.Exists("/bundle/production-v1"))
    {
        using var production = LdapWorkerDeployment.Validate("/bundle/production-v1");
        production.RequireRestrictedComposition();
    }
    Console.WriteLine("PASS: managed runtime and immutable bundle admission/retention; malformed bundles refused before credentials.");
    return 0;
}
if (args is ["--real-public-lab"]) return await RealPublicLab.Run();
if (args is ["--real-lab-parent"]) return await RealLabWorker.Parent();
// The admitted test bundle uses the same fixed host+supervisor argv contract as NativeHost.
if (args is ["/bundle/lab-v1/host/libadfl_worker.so", "/bundle/lab-v1"]) return await RealLabWorker.Child();
if (args is ["--real-lab-child"]) return await RealLabWorker.Child();

if (OfflineTestGuard.Enabled && args is ["--generate-lab-profile"])
{
    Console.Write(Encoding.ASCII.GetString(new LdapWorkerKerberosProfile("ADFL.TEST", "127.0.0.1", "/run/adfl/plugins",
        new("127.0.0.1", 10088)).Generate("127.0.0.1")));
    return 0;
}
if (args.FirstOrDefault() == "--child") return await Child(args);
if (!OfflineTestGuard.Enabled || args.Length is not (4 or 5)) throw new InvalidOperationException("Use the offline worker runner with dotnet, supervisor, recording bridge and production host paths.");
var executable = Path.GetFullPath(args[0]);
var supervisorPath = Path.GetFullPath(args[1]);
var bridgePath = Path.GetFullPath(args[2]);
var productionHost = Path.GetFullPath(args[3]);
var assembly = typeof(Program).Assembly.Location;
var profileProbe = args.Length == 5 ? Path.GetFullPath(args[4]) : "";
var profile = new LdapWorkerStart("directory.invalid", 389, false, true, true, 2, TimeSpan.FromSeconds(5), new(LdapCredentialSourceKind.File, "/recording/worker-cache"),
    new("EXAMPLE.INVALID", "directory.invalid", "/recording/private-plugins", new("127.0.0.1", 10088)));
WorkerLaunch Launch(string mode) => new(executable, [assembly, "--child", supervisorPath, bridgePath, mode, profileProbe], supervisorPath);
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
if (profileProbe.Length != 0) Console.WriteLine("PASS: sealed restricted configuration consumed by private MIT profile reads and GSS mechanism metadata; no credential acquisition.");
using (var lease = await workers.AcquireAsync(Launch("normal"), profile with
    { CredentialSource = new(LdapCredentialSourceKind.DirectoryCollection, "/recording/collection") }, TimeSpan.FromSeconds(5)))
    if (LdapRequestDispatcher.Search(lease.Client.Sessions[1], read).Entries.Length != 1)
        throw new InvalidOperationException("Explicit DIR source worker failed.");
await Empty();
Console.WriteLine("PASS: synthetic FILE/DIR source recipes cross START and native resolve_from once for paired sessions; no source files are opened.");

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
foreach (var mode in new[] { "unsealed-profile", "partial-profile", "future-write-profile" })
{
    try { using var bad = await workers.AcquireAsync(Launch(mode), profile, TimeSpan.FromSeconds(3)); throw new InvalidOperationException("Mutable profile admitted."); }
    catch (IOException error) when (error.Message == "Worker operation failed.") { }
    await Empty();
}
Console.WriteLine("PASS: identical profile bytes with absent, partial, or FUTURE_WRITE-only seals are refused before the backend factory.");
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
    if (!OfflineTestGuard.Enabled || arguments.Length != 5 ||
        Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") != "0") return 2;
    var mode = arguments[3];
    if (mode == "late-identity") await Task.Delay(700);
    using var native = new WorkerNative(arguments[1]);
    if (native.SendIdentity(3) != 0) return 3;
    using var socket = new Socket(new SafeSocketHandle((IntPtr)3, ownsHandle: true));
    using var channel = new NetworkStream(socket, ownsSocket: false);
    if (mode == "exit") return 0;
    if (mode == "malformed") { await channel.WriteAsync(new byte[] { 255, 255, 255, 127 }); await Task.Delay(5000); return 0; }
    if (mode is "unsealed-profile" or "partial-profile" or "future-write-profile")
        ProfileFixture.ReplaceWithMutableCopy(mode);
    if (arguments[4].Length != 0)
    {
        // Separate test-only private MIT module; no cache/credential operations.
        // Retain until process exit because upstream libraries own process state.
        var probeLibrary = NativeLibrary.Load(arguments[4]);
        var inspect = Marshal.GetDelegateForFunctionPointer<InspectProfile>(NativeLibrary.GetExport(probeLibrary, "adfl_test_private_profile"));
        if (inspect() != 0) return 6;
    }
    var library = NativeLibrary.Load(arguments[2]);
    NativeLibrary.SetDllImportResolver(typeof(NativeLdapBindingBackend).Assembly, (name, _, _) => name == "adfl_native" ? library : IntPtr.Zero);
    var configure = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_configure"));
    var block = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_set_block"));
    if (configure(1) != 0 || block(mode switch { "blocked-read" => 1, "before-write" => 2, "after-write" => 3, _ => 0 }) != 0) return 4;
    var api = new RecordingBindingApi(library);
    var sourcePath = Marshal.GetDelegateForFunctionPointer<SourcePath>(NativeLibrary.GetExport(library, "adfl_test_source_path"));
    var sourceCount = Marshal.GetDelegateForFunctionPointer<Configure>(NativeLibrary.GetExport(library, "adfl_test_count"));
    using var pool = new BoundedConnectionPool<LdapConnectionProvider.ConnectionKey, BoundLdapSession>(2, 2, startTimer: false);
    try
    {
        await LdapWorkerHost.RunAsync(channel, start =>
        {
            if (mode is "unsealed-profile" or "partial-profile" or "future-write-profile")
                throw new PlatformNotSupportedException("Fixture factory must not be reached for mutable profiles.");
            var options = new LdapConnectionOptions { Host = start.Host, Port = start.Port, UseSsl = start.UseSsl,
                AuthenticationType = AuthType.Negotiate, Signing = start.Signing, Sealing = start.Sealing, Timeout = start.Timeout };
            var owner = NativeLdapOperation.Acquire(pool, options, start.SessionCount, api: api, source: start.CredentialSource);
            if (start.CredentialSource is { } source && (sourceCount(10) != 1 || sourceCount(12) != 1 ||
                sourceCount(11) != (int)source.Kind || Marshal.PtrToStringUTF8(sourcePath()) != source.AbsolutePath))
            { owner.Dispose(); throw new InvalidOperationException("Native source recipe was not consumed exactly once."); }
            return new LdapWorkerResources(owner, owner.Sessions.Select(session => session.ExecuteTransport(value => value)).ToArray());
        }, CancellationToken.None);
        return 0;
    }
    catch { return 5; }
}
[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Configure(int value);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr SourcePath();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int InspectProfile();

// Only disposable recording child processes replace inherited descriptors.
static class ProfileFixture
{
    internal static void ReplaceWithMutableCopy(string mode)
    {
        using var original = new SafeFileHandle((IntPtr)4, ownsHandle: false);
        var data = new byte[checked((int)RandomAccess.GetLength(original))];
        if (RandomAccess.Read(original, data, 0) != data.Length) throw new IOException("Fixture read failed.");
        var fd = MemfdCreate("adfl-unsealed-test", 3 /* CLOEXEC | ALLOW_SEALING */);
        if (fd < 6) throw new IOException("Fixture memfd failed.");
        using var replacement = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        RandomAccess.Write(replacement, data, 0);
        var seals = mode switch { "partial-profile" => 7, "future-write-profile" => 23, _ => 0 };
        if ((seals != 0 && Fcntl(fd, 1033 /* F_ADD_SEALS */, seals) != 0) || Dup2(fd, 4) != 4)
            throw new IOException("Fixture seal/dup failed.");
    }
    [DllImport("libc", EntryPoint = "memfd_create")] private static extern int MemfdCreate(string name, uint flags);
    [DllImport("libc", EntryPoint = "fcntl")] private static extern int Fcntl(int fd, int command, int value);
    [DllImport("libc", EntryPoint = "dup2")] private static extern int Dup2(int fd, int destination);
}
