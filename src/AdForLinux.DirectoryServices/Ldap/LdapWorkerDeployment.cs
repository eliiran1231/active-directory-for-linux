using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

// Administrator-owned immutable version directories only. The OS/runtime and
// administrator are trusted: a version must never be mutated, replaced, unmounted
// or removed while workers use it. Held descriptors do NOT make pathname-based
// exec/loader resolution safe against a malicious administrator.
internal static class LdapWorkerDeployment
{
    private const int MaximumManifestBytes = 4 * 1024 * 1024;
    private const int MaximumFiles = 32768;
    private const ulong MaximumFileBytes = 512UL * 1024 * 1024;
    private const ulong MaximumBundleBytes = 2UL * 1024 * 1024 * 1024;
    internal sealed record Artifact(string Path, string Sha256);
    internal sealed record Roles(string Dotnet, string HostAssembly, string Supervisor, string NativeBridge);
    internal sealed record Manifest(int FormatVersion, string Version, Roles Roles, Artifact[] Artifacts);

    internal static VerifiedDeployment Validate(string directory)
    {
        RequireUnprivilegedLinux();
        if (string.IsNullOrEmpty(directory) || !Path.IsPathFullyQualified(directory) || directory == "/" ||
            directory != Path.GetFullPath(directory) || directory.EndsWith('/') || directory.Contains('\0'))
            throw new ArgumentException("Deployment requires a canonical absolute version directory.");
        var handles = new List<SafeFileHandle>();
        try
        {
            CheckAncestors(directory);
            var manifestPath = Path.Combine(directory, "manifest.json");
            var manifestHandle = OpenVerified(manifestPath, out var manifestStat);
            handles.Add(manifestHandle);
            if (manifestStat.Size > MaximumManifestBytes) throw new InvalidDataException("Deployment manifest exceeds limit.");
            var bytes = new byte[checked((int)manifestStat.Size)];
            ReadExact(manifestHandle, bytes);
            RequireUnchanged(manifestPath, manifestHandle, manifestStat);
            var manifest = Parse(bytes);
            var remaining = manifest.Artifacts.ToDictionary(value => value.Path, StringComparer.Ordinal);
            ulong total = 0;
            var directories = new Stack<string>(); directories.Push(directory);
            var count = 0;
            while (directories.TryPop(out var current))
            {
                foreach (var path in Directory.EnumerateFileSystemEntries(current))
                {
                    if (++count > MaximumFiles * 2) throw new InvalidDataException("Deployment inventory exceeds limit.");
                    var stat = Inspect(path); var type = stat.Mode & 0xf000;
                    if (type == 0x4000) { RequireMetadata(stat, directory: true); directories.Push(path); continue; }
                    RequireMetadata(stat, directory: false);
                    var relative = Path.GetRelativePath(directory, path);
                    if (relative == "manifest.json") continue;
                    if (!remaining.Remove(relative, out var artifact)) throw new InvalidDataException("Undeclared deployment artifact.");
                    var handle = OpenVerified(path, out var opened); handles.Add(handle);
                    if (opened.Size > MaximumFileBytes || (total += opened.Size) > MaximumBundleBytes)
                        throw new InvalidDataException("Deployment artifact bytes exceed limit.");
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[64 * 1024]; long offset = 0;
                    while ((ulong)offset < opened.Size)
                    {
                        var read = RandomAccess.Read(handle, buffer.AsSpan(0, (int)Math.Min((ulong)buffer.Length, opened.Size - (ulong)offset)), offset);
                        if (read == 0) throw new EndOfStreamException("Deployment artifact changed while hashing.");
                        hash.AppendData(buffer, 0, read); offset += read;
                    }
                    if (!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(artifact.Sha256)))
                        throw new InvalidDataException("Deployment artifact digest mismatch.");
                    RequireUnchanged(path, handle, opened);
                }
            }
            if (remaining.Count != 0) throw new InvalidDataException("Deployment artifact is missing.");
            RequireUnchanged(manifestPath, manifestHandle, manifestStat);
            CheckAncestors(directory);
            var roles = manifest.Roles;
            var executable = Path.Combine(directory, roles.Dotnet);
            if (EffectiveAccess(-100, executable, 1 /* X_OK */, 0x200 /* AT_EACCESS */) != 0)
                throw new InvalidDataException("Deployment dotnet role is not executable by this caller.");
            return new VerifiedDeployment(manifest.Version,
                new WorkerLaunch(executable, [Path.Combine(directory, roles.HostAssembly), Path.Combine(directory, roles.Supervisor), directory], Path.Combine(directory, roles.Supervisor)),
                Path.Combine(directory, roles.NativeBridge), handles, manifest.Artifacts.ToDictionary(artifact => artifact.Path, artifact => Path.Combine(directory, artifact.Path), StringComparer.Ordinal),
                manifest.Artifacts.Single(artifact => artifact.Path == roles.NativeBridge).Sha256);
        }
        catch { foreach (var handle in handles) handle.Dispose(); throw; }
    }

    internal static Manifest Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaximumManifestBytes) throw new InvalidDataException("Deployment manifest exceeds limit.");
        using var json = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        CheckObject(json.RootElement, "FormatVersion", "Version", "Roles", "Artifacts");
        var root = json.RootElement;
        if (root.GetProperty("FormatVersion").GetInt32() != 1) throw new InvalidDataException("Unsupported deployment format.");
        var version = root.GetProperty("Version").GetString();
        if (string.IsNullOrEmpty(version) || version.Length > 128 || version.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_' and not '.'))
            throw new InvalidDataException("Invalid deployment version.");
        var rolesJson = root.GetProperty("Roles"); CheckObject(rolesJson, "Dotnet", "HostAssembly", "Supervisor", "NativeBridge");
        string Role(string name) => Relative(rolesJson.GetProperty(name).GetString());
        var roles = new Roles(Role("Dotnet"), Role("HostAssembly"), Role("Supervisor"), Role("NativeBridge"));
        var array = root.GetProperty("Artifacts");
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 4 or > MaximumFiles)
            throw new InvalidDataException("Invalid deployment inventory size.");
        var artifacts = new List<Artifact>(); var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in array.EnumerateArray())
        {
            CheckObject(item, "Path", "Sha256"); var path = Relative(item.GetProperty("Path").GetString());
            var digest = item.GetProperty("Sha256").GetString();
            if (path == "manifest.json" || !paths.Add(path) || digest is null || digest.Length != 64 || !digest.All(Uri.IsHexDigit))
                throw new InvalidDataException("Invalid or duplicate deployment artifact.");
            artifacts.Add(new(path, digest));
        }
        var rolePaths = new[] { roles.Dotnet, roles.HostAssembly, roles.Supervisor, roles.NativeBridge };
        if (rolePaths.Distinct(StringComparer.Ordinal).Count() != 4 || rolePaths.Any(path => !paths.Contains(path)))
            throw new InvalidDataException("Deployment roles must identify distinct declared artifacts.");
        return new(1, version, roles, artifacts.ToArray());
    }
    private static void CheckObject(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected deployment object.");
        var remaining = names.ToHashSet(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!remaining.Remove(property.Name)) throw new InvalidDataException("Unknown or duplicate deployment property.");
        if (remaining.Count != 0) throw new InvalidDataException("Missing deployment property.");
    }
    private static string Relative(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Length > 1024 || path.Split('/').Any(part => part is "" or "." or ".." ||
            part.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-' and not '_')))
            throw new InvalidDataException("Deployment artifact paths must be safe relative paths.");
        return path;
    }
    private static void RequireUnprivilegedLinux()
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64) ||
            GetResUid(out var real, out var effective, out var saved) != 0 ||
            GetResGid(out var realGroup, out var effectiveGroup, out var savedGroup) != 0)
            throw new PlatformNotSupportedException("Deployment admission requires verifiable Linux x64/arm64 caller identity.");
        // Linux auxvec.h AT_SECURE=23. Check even after IDs were made equal:
        // secure-execution mode survives such changes and secure_getenv can
        // ignore the sealed KRB5_CONFIG/GSS_MECH_CONFIG environment recipe.
        var secure = GetAuxVal(23);
        if (Marshal.GetLastPInvokeError() != 0)
            throw new PlatformNotSupportedException("Deployment admission cannot establish secure-execution state.");
        var status = File.ReadLines("/proc/thread-self/status").Where(line => line.StartsWith("CapPrm:", StringComparison.Ordinal) || line.StartsWith("CapEff:", StringComparison.Ordinal)).ToArray();
        ulong Capabilities(string name)
        {
            var matching = status.Where(line => line.StartsWith(name + ":", StringComparison.Ordinal)).ToArray();
            if (matching.Length != 1 || !ulong.TryParse(matching[0].AsSpan(name.Length + 1).Trim(), NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture, out var value))
                throw new PlatformNotSupportedException("Deployment admission cannot establish caller capabilities.");
            return value;
        }
        RequireCallerPolicy(real, effective, saved, realGroup, effectiveGroup, savedGroup,
            (ulong)secure, Capabilities("CapPrm"), Capabilities("CapEff"));
    }
    // Pure policy seam: deterministic tests never change IDs, capabilities or
    // secure-execution state. Actual admission always obtains these via libc/proc.
    internal static void RequireCallerPolicy(uint real, uint effective, uint saved,
        uint realGroup, uint effectiveGroup, uint savedGroup, ulong secure, ulong permitted, ulong active)
    {
        if (real == 0 || real != effective || real != saved || realGroup != effectiveGroup || realGroup != savedGroup ||
            secure != 0 || permitted != 0 || active != 0)
            throw new PlatformNotSupportedException("Deployment admission refuses root, differing real/effective/saved IDs, secure execution or capabilities.");
    }
    private static void CheckAncestors(string path)
    {
        RequireMetadata(Inspect("/"), true);
        var current = "";
        foreach (var component in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        { current += "/" + component; RequireMetadata(Inspect(current), true); }
    }
    private static void RequireMetadata(Statx stat, bool directory)
    {
        const uint required = 0x3cb; // TYPE MODE UID MTIME CTIME INO SIZE
        if ((stat.Mask & required) != required || stat.Uid != 0 || (stat.Mode & 0x12) != 0 ||
            (stat.Mode & 0xf000) != (directory ? 0x4000 : 0x8000) || (!directory && (stat.Mode & 0xc00) != 0))
            throw new InvalidDataException("Deployment metadata is not administrator-owned immutable policy.");
    }
    private static SafeFileHandle OpenVerified(string path, out Statx stat)
    {
        stat = Inspect(path); RequireMetadata(stat, false);
        var descriptor = Open(path, 0x80000 | 0x20000 | 0x800); // CLOEXEC NOFOLLOW NONBLOCK, read-only
        if (descriptor < 0) throw new IOException("Cannot open deployment artifact.");
        var handle = new SafeFileHandle((IntPtr)descriptor, true);
        try
        {
            RequireUnchanged(path, handle, stat);
            var capabilities = FGetXAttr(descriptor, "security.capability", IntPtr.Zero, UIntPtr.Zero);
            // ENODATA/ENOTSUP only; unknown metadata failure is not eligibility.
            if (capabilities >= 0 || Marshal.GetLastPInvokeError() is not (61 or 95))
                throw new InvalidDataException("Deployment artifact has capabilities or unverifiable capability metadata.");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }
    private static void ReadExact(SafeFileHandle handle, byte[] bytes)
    {
        var offset = 0;
        while (offset < bytes.Length)
        { var read = RandomAccess.Read(handle, bytes.AsSpan(offset), offset); if (read == 0) throw new EndOfStreamException(); offset += read; }
    }
    private static void RequireUnchanged(string path, SafeFileHandle handle, Statx before)
    {
        var descriptor = checked((int)handle.DangerousGetHandle());
        var opened = Inspect("", descriptor, 0x1000); // AT_EMPTY_PATH
        RequireMetadata(opened, false);
        if (!Same(before, opened) || !Same(opened, Inspect(path))) throw new IOException("Deployment artifact changed during admission.");
    }
    private static bool Same(Statx a, Statx b) => a.Inode == b.Inode && a.DeviceMajor == b.DeviceMajor && a.DeviceMinor == b.DeviceMinor &&
        a.Mode == b.Mode && a.Uid == b.Uid && a.Size == b.Size && a.ModifiedSeconds == b.ModifiedSeconds && a.ModifiedNanoseconds == b.ModifiedNanoseconds &&
        a.ChangedSeconds == b.ChangedSeconds && a.ChangedNanoseconds == b.ChangedNanoseconds;
    private static Statx Inspect(string path, int directory = -100, int flags = 0x100) // AT_FDCWD, AT_SYMLINK_NOFOLLOW
    {
        if (NativeStatx(directory, path, flags, 0x7ff, out var stat) != 0) throw new IOException("Cannot inspect deployment metadata.");
        return stat;
    }
    // Linux UAPI /usr/include/linux/stat.h: fixed 256-byte statx; offsets are
    // architecture-independent (unlike libc struct stat). No unverified helper.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(20)] internal uint Uid;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(40)] internal ulong Size;
        [FieldOffset(96)] internal long ChangedSeconds;
        [FieldOffset(104)] internal uint ChangedNanoseconds;
        [FieldOffset(112)] internal long ModifiedSeconds;
        [FieldOffset(120)] internal uint ModifiedNanoseconds;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
    }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)] private static extern int NativeStatx(int dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Statx result);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "fgetxattr", SetLastError = true)] private static extern nint FGetXAttr(int fd, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, IntPtr value, UIntPtr size);
    [DllImport("libc", EntryPoint = "faccessat", SetLastError = true)] private static extern int EffectiveAccess(int dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int mode, int flags);
    [DllImport("libc", EntryPoint = "getresuid")] private static extern int GetResUid(out uint real, out uint effective, out uint saved);
    [DllImport("libc", EntryPoint = "getresgid")] private static extern int GetResGid(out uint real, out uint effective, out uint saved);
    // SetLastError clears errno before the call on supported .NET, preserving
    // the distinction between a present zero value and a missing auxv entry.
    [DllImport("libc", EntryPoint = "getauxval", SetLastError = true)] private static extern nuint GetAuxVal(nuint type);
}

// Opaque validated authority, retaining artifact handles until all admitted
// workers release their references. This does not activate the backend.
internal sealed partial class VerifiedDeployment : IDisposable
{
    private readonly WorkerLaunch launch;
    private readonly SafeFileHandle[] handles;
    private readonly IReadOnlyDictionary<string, string> artifacts;
    private readonly string nativeBridgeSha256;
    private int references = 1, disposed;
    internal string Version { get; }
    internal string NativeBridgePath { get; }
    internal VerifiedDeployment(string version, WorkerLaunch launch, string nativeBridge, List<SafeFileHandle> handles, IReadOnlyDictionary<string, string> artifacts, string nativeBridgeSha256)
    { this.nativeBridgeSha256 = nativeBridgeSha256; Version = version; this.launch = launch; NativeBridgePath = nativeBridge; this.handles = handles.ToArray(); this.artifacts = artifacts; }
    internal string GetArtifact(string relativePath)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return artifacts.TryGetValue(relativePath, out var path) ? path : throw new ArgumentException("Artifact was not admitted by this deployment.");
    }
    internal WorkerLaunch CreateLaunch()
    { ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); return launch with { Arguments = launch.Arguments.ToArray() }; }
    internal IDisposable Retain()
    {
        while (true)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            var current = Volatile.Read(ref references);
            if (current == 0) throw new ObjectDisposedException(nameof(VerifiedDeployment));
            if (Interlocked.CompareExchange(ref references, current + 1, current) == current) return new Reference(this);
        }
    }
    private void Release() { if (Interlocked.Decrement(ref references) == 0) foreach (var handle in handles) handle.Dispose(); }
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) Release(); }
    private sealed class Reference(VerifiedDeployment owner) : IDisposable
    {
        private VerifiedDeployment? retained = owner;
        public void Dispose() => Interlocked.Exchange(ref retained, null)?.Release();
    }
}
