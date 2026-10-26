using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

// Worker lifetime is separate from its exclusive operation lease. Current policy
// retires on lease disposal; future reuse requires an independent authority proof.
internal sealed class NativeLdapWorkerPool : IDisposable
{
    private readonly SemaphoreSlim capacity;
    private readonly object admissionGate = new();
    private readonly ConcurrentDictionary<WorkerOwner, byte> owners = new();
    private int disposed;
    internal NativeLdapWorkerPool(int maximumWorkers)
    {
        if (maximumWorkers <= 0) throw new ArgumentOutOfRangeException(nameof(maximumWorkers));
        capacity = new(maximumWorkers, maximumWorkers);
    }
    internal (int Tracked, int Retiring, int Unverified) Snapshot =>
        (owners.Count, owners.Keys.Count(owner => owner.Retired), owners.Keys.Count(owner => !owner.IdentityVerified));

    internal async Task<WorkerLease> AcquireAsync(WorkerLaunch launch, LdapWorkerStart profile,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Worker authority transfer is implemented only for Linux; Windows impersonation is not transferred.");
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromHours(1)) throw new ArgumentOutOfRangeException(nameof(timeout));
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        LdapWorkerProtocol.ValidateStart(profile);
        launch.Validate();
        launch = launch with { Arguments = launch.Arguments.ToArray() };
        var started = Stopwatch.GetTimestamp();
        TimeSpan Remaining() => timeout - Stopwatch.GetElapsedTime(started);
        if (!await capacity.WaitAsync(timeout, cancellationToken).ConfigureAwait(false)) throw new TimeoutException("Worker capacity is occupied, including retiring workers.");
        WorkerOwner? owner = null;
        try
        {
            Task<NetworkStream> startup;
            lock (admissionGate)
            {
                ObjectDisposedException.ThrowIf(disposed != 0, this);
                owner = new WorkerOwner(launch, profile, Released);
                owners.TryAdd(owner, 0);
                startup = owner.StartAsync();
            }
            _ = startup.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            var left = Remaining();
            if (left <= TimeSpan.Zero) throw new TimeoutException("Worker startup deadline expired.");
            var stream = await startup.WaitAsync(left, cancellationToken).ConfigureAwait(false);
            left = Remaining();
            if (left <= TimeSpan.Zero) throw new TimeoutException("Worker startup deadline expired.");
            var client = await LdapWorkerClient.StartAsync(stream, owner.Retire, profile, left, cancellationToken).ConfigureAwait(false);
            return new WorkerLease(owner, client);
        }
        catch
        {
            if (owner is null) capacity.Release(); else owner.Retire();
            throw;
        }
    }
    private void Released(WorkerOwner owner)
    {
        if (owners.TryRemove(owner, out _)) capacity.Release();
    }
    public void Dispose()
    {
        WorkerOwner[] active;
        lock (admissionGate)
        {
            if (disposed != 0) return;
            disposed = 1; active = owners.Keys.ToArray();
        }
        foreach (var owner in active) owner.Retire();
        // Pending startup and reaping retain capacity/ownership until confirmed.
        // Do not dispose the semaphore while completion callbacks can release it.
    }

    internal sealed class WorkerLease : IDisposable
    {
        private readonly WorkerOwner owner;
        private int disposed;
        internal WorkerLease(WorkerOwner owner, LdapWorkerClient client) { this.owner = owner; Client = client; }
        internal LdapWorkerClient Client { get; }
        internal Task Cleanup => owner.Cleanup;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            Client.Dispose(); owner.Retire();
        }
    }

    internal sealed class WorkerOwner(WorkerLaunch launch, LdapWorkerStart profile, Action<WorkerOwner> released)
    {
        private readonly TaskCompletionSource cleanup = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object stateGate = new();
        private WorkerNative? api;
        private NetworkStream? stream;
        private int channel = -1, pidfd = -1, retired, cleanupStarted, finished;
        internal bool Retired => Volatile.Read(ref retired) != 0;
        internal bool IdentityVerified => Volatile.Read(ref pidfd) >= 0;
        internal Task Cleanup => cleanup.Task;
        internal Task<NetworkStream> StartAsync() => Task.Run(async () =>
        {
            var spawned = false;
            try
            {
                api = new WorkerNative(launch.SupervisorLibrary);
                using var argv = new WorkerStrings([launch.Executable, .. launch.Arguments]);
                // Generated configuration is installed before exec: GSS creates
                // contexts independently of the resolver. No parent environment is changed.
                using var configuration = new WorkerProfileFiles(api, profile);
                using var env = new WorkerStrings(["DOTNET_EnableDiagnostics=0", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_GENERATE_ASPNET_CERTIFICATE=false", "ADFL_OFFLINE_TESTS=1", .. configuration.Environment]);
                var error = api.Spawn(launch.Executable, argv.Pointer, env.Pointer, configuration.Config, configuration.Mechanisms, out channel, out var child);
                configuration.Dispose(); // child owns independent fd4/5 after successful exec
                if (error != 0) throw new InvalidOperationException($"Worker exec failed ({error}).");
                spawned = true;
                while (true)
                {
                    error = api.Receive(channel, child, out var received);
                    if (error == 0)
                    {
                        lock (stateGate)
                        {
                            Volatile.Write(ref pidfd, received);
                            var handle = new SafeSocketHandle((IntPtr)channel, ownsHandle: true);
                            channel = -1;
                            Socket socket;
                            try { socket = new Socket(handle); } catch { handle.Dispose(); throw; }
                            try { stream = new NetworkStream(socket, ownsSocket: true); }
                            catch { socket.Dispose(); throw; }
                        }
                        break;
                    }
                    if (error is not (11 or 4)) throw new InvalidOperationException($"Worker identity handoff failed ({error}); termination remains unverified.");
                    // Continue owning startup even if the caller timed out. Only a
                    // verified pidfd permits termination; never rediscover by PID.
                    await Task.Delay(10).ConfigureAwait(false);
                }
                if (Retired) { ScheduleCleanup(); throw new OperationCanceledException("Worker was retired during startup."); }
                return stream!;
            }
            catch
            {
                Interlocked.Exchange(ref retired, 1);
                if (Volatile.Read(ref cleanupStarted) != 0) { }
                else if (IdentityVerified) ScheduleCleanup();
                else if (!spawned) Finish();
                else
                {
                    // An exited/hung child without handoff cannot be safely
                    // signalled/reaped via this API. Quarantine its capacity.
                    if (channel >= 0) { api?.Close(channel); channel = -1; }
                }
                throw;
            }
        });
        internal void Retire()
        {
            lock (stateGate)
            {
                Interlocked.Exchange(ref retired, 1);
                if (IdentityVerified) ScheduleCleanup();
            }
        }
        private void ScheduleCleanup()
        {
            if (Interlocked.Exchange(ref cleanupStarted, 1) != 0) return;
            _ = Task.Run(async () =>
            {
                // Caller return never awaits signal, close, drain, or OS reaping.
                try { api!.Kill(pidfd); } catch { /* retain slot until exit proven */ }
                try { stream?.Dispose(); } catch { }
                while (true)
                {
                    var status = api!.Reap(pidfd);
                    if (status == 0) { Finish(); return; } // verified exit, possibly reaped elsewhere
                    // EAGAIN or uncertain errors keep the bounded slot occupied.
                    await Task.Delay(25).ConfigureAwait(false);
                }
            });
        }
        private void Finish()
        {
            if (Interlocked.Exchange(ref finished, 1) != 0) return;
            if (channel >= 0) { api?.Close(channel); channel = -1; }
            if (pidfd >= 0) { api?.Close(pidfd); pidfd = -1; }
            api?.Dispose(); released(this); cleanup.TrySetResult();
        }
    }
}

internal sealed record WorkerLaunch(string Executable, string[] Arguments, string SupervisorLibrary)
{
    internal void Validate()
    {
        if (!Path.IsPathFullyQualified(Executable) || !Path.IsPathFullyQualified(SupervisorLibrary) ||
            Executable.Length > 4096 || SupervisorLibrary.Length > 4096 ||
            Executable.Contains('\0') || SupervisorLibrary.Contains('\0') || Arguments.Length > 32 ||
            Arguments.Any(value => value is null || value.Contains('\0') || value.Length > 32768))
            throw new ArgumentException("Worker launch requires exact paths and bounded literal arguments; no shell is used.");
    }
}

// libc-only supervisor: loading this module does not initialize LDAP/SASL/GSS.
internal sealed class WorkerNative : IDisposable
{
    private readonly IntPtr library;
    internal readonly SpawnCall Spawn;
    internal readonly ReceiveCall Receive;
    internal readonly ProfileCall CreateProfile;
    internal readonly FdCall Kill, Reap, Close, SendIdentity;
    internal WorkerNative(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute supervisor path is required.");
        library = NativeLibrary.Load(path);
        try
        {
            T Get<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            if (Get<VersionCall>("adfl_worker_abi_version")() != 2) throw new PlatformNotSupportedException("Unsupported worker supervisor ABI.");
            CreateProfile = Get<ProfileCall>("adfl_worker_profile_create");
            Spawn = Get<SpawnCall>("adfl_worker_spawn"); Receive = Get<ReceiveCall>("adfl_worker_parent_receive_identity");
            Kill = Get<FdCall>("adfl_worker_signal_kill"); Reap = Get<FdCall>("adfl_worker_reap_nonblocking");
            Close = Get<FdCall>("adfl_worker_closefd"); SendIdentity = Get<FdCall>("adfl_worker_child_send_identity");
        }
        catch { NativeLibrary.Free(library); throw; }
    }
    public void Dispose() => NativeLibrary.Free(library);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint VersionCall();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int SpawnCall([MarshalAs(UnmanagedType.LPUTF8Str)] string executable, IntPtr argv, IntPtr environment, int configuration, int mechanisms, out int channel, out int childPid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int ProfileCall(byte[] bytes, UIntPtr length, out int descriptor);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int ReceiveCall(int channel, int expectedChildPid, out int pidfd);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int FdCall(int fd);
}
// Parent copies are startup-owned and closed on every spawn path. Child fd4/5
// remain process-owned across operation leases and are released by worker exit.
internal sealed class WorkerProfileFiles : IDisposable
{
    private readonly WorkerNative api;
    internal int Config { get; private set; } = -1;
    internal int Mechanisms { get; private set; } = -1;
    internal string[] Environment => Config < 0 ? [] : ["KRB5_CONFIG=/proc/self/fd/4", "GSS_MECH_CONFIG=/proc/self/fd/5"];
    internal WorkerProfileFiles(WorkerNative api, LdapWorkerStart profile)
    {
        this.api = api;
        if (profile.RestrictedConfiguration is not { } configuration) return;
        try
        {
            var bytes = configuration.Generate(profile.Host);
            var status = api.CreateProfile(bytes, (UIntPtr)bytes.Length, out var descriptor);
            if (status != 0) throw new IOException($"Creating sealed worker profile failed ({status}).");
            Config = descriptor;
            status = api.CreateProfile([], UIntPtr.Zero, out descriptor);
            if (status != 0) throw new IOException($"Creating sealed mechanism profile failed ({status}).");
            Mechanisms = descriptor;
        }
        catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        if (Config >= 0) { api.Close(Config); Config = -1; }
        if (Mechanisms >= 0) { api.Close(Mechanisms); Mechanisms = -1; }
    }
}
internal sealed class WorkerStrings : IDisposable
{
    private readonly List<IntPtr> strings = [];
    internal IntPtr Pointer { get; }
    internal WorkerStrings(string[] values)
    {
        Pointer = Marshal.AllocHGlobal(checked((values.Length + 1) * IntPtr.Size));
        try
        {
            for (var i = 0; i < values.Length; i++)
            { var value = Marshal.StringToCoTaskMemUTF8(values[i]); strings.Add(value); Marshal.WriteIntPtr(Pointer, i * IntPtr.Size, value); }
            Marshal.WriteIntPtr(Pointer, values.Length * IntPtr.Size, IntPtr.Zero);
        }
        catch { Dispose(); throw; }
    }
    public void Dispose() { foreach (var value in strings) Marshal.FreeCoTaskMem(value); strings.Clear(); Marshal.FreeHGlobal(Pointer); }
}
