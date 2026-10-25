using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace AdForLinux.DirectoryServices.Ldap;

// A token object/modification fingerprint, not an assertion of equivalent rights.
// Pool lifetime is process-local; identifiers are never persisted or logged.
internal readonly record struct WindowsLdapContext(
    ulong TokenId, ulong AuthenticationId, ulong ModifiedId,
    uint TokenType, uint ImpersonationLevel, bool ThreadToken)
{
    public override string ToString() => "Windows LDAP context (redacted)";
}

internal static class WindowsLdapContextQuery
{
    private const uint TokenQuery = 8;
    internal const uint QuerySentinel = 0x5a5a5a5a;
    private const int NoToken = 1008, InsufficientBuffer = 122;
    [StructLayout(LayoutKind.Sequential)]
    internal struct Statistics
    {
        internal ulong TokenId, AuthenticationId;
        internal long Expiration;
        internal uint TokenType, ImpersonationLevel, DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
        internal ulong ModifiedId;
    }

    internal readonly record struct QueryDiagnostic(string Stage, string Kind, int Code);
    internal static WindowsLdapContext? Capture() => Capture(out _);
    internal static WindowsLdapContext? Capture(out QueryDiagnostic diagnostic) => CaptureCore(true, out diagnostic);
    // Read-only regression comparison only; ordinary callers use the validated decoder.
    internal static WindowsLdapContext? CaptureStrictLengthDiagnostic(out QueryDiagnostic diagnostic)
        => CaptureCore(false, out diagnostic);
    private static WindowsLdapContext? CaptureCore(bool scalarLayout, out QueryDiagnostic diagnostic)
    {
        diagnostic = new("guard", "none", 0);
        if (OfflineTestGuard.Enabled) return Reject(out diagnostic, "offline");
        if (!OperatingSystem.IsWindows()) return Reject(out diagnostic, "platform");
        string stage = "open-thread";
        try
        {
            bool thread = true;
            if (!OpenThreadToken(new IntPtr(-2), TokenQuery, true, out var handle))
            {
                int error = Marshal.GetLastWin32Error();
                handle?.Dispose();
                if (!CanUseProcessToken(error)) return Reject(out diagnostic, stage, "win32", error);
                thread = false; stage = "open-process";
                if (!OpenProcessToken(new IntPtr(-1), TokenQuery, out handle))
                {
                    error = Marshal.GetLastWin32Error(); handle?.Dispose();
                    return Reject(out diagnostic, stage, "win32", error);
                }
            }
            using (handle)
            {
                stage = "statistics-before";
                if (!GetStatistics(handle, 10, out var before, (uint)Marshal.SizeOf<Statistics>(), out var size))
                    return Reject(out diagnostic, stage, "win32", Marshal.GetLastWin32Error());
                if (size != Marshal.SizeOf<Statistics>()) return Reject(out diagnostic, "statistics-before-length");
                stage = "restrictions";
                uint restricted = QuerySentinel;
                size = QuerySentinel;
                if (!GetFlag(handle, 21, ref restricted, sizeof(uint), ref size))
                    return Reject(out diagnostic, stage, "win32", Marshal.GetLastWin32Error());
                if (!scalarLayout && (size != 4 || restricted == QuerySentinel))
                    return Reject(out diagnostic, "restrictions-length", "length", unchecked((int)size));
                if (scalarLayout)
                {
                    var normalized = DecodeScalarFlag(restricted, size);
                    if (!normalized.HasValue) return Reject(out diagnostic, "restrictions-format", "length", unchecked((int)size));
                    restricted = normalized.Value;
                }
                stage = "app-container";
                uint container = QuerySentinel;
                size = QuerySentinel;
                if (!GetFlag(handle, 29, ref container, sizeof(uint), ref size))
                    return Reject(out diagnostic, stage, "win32", Marshal.GetLastWin32Error());
                if (!scalarLayout && (size != 4 || container == QuerySentinel))
                    return Reject(out diagnostic, "app-container-length", "length", unchecked((int)size));
                if (scalarLayout)
                {
                    var normalized = DecodeScalarFlag(container, size);
                    if (!normalized.HasValue) return Reject(out diagnostic, "app-container-format", "length", unchecked((int)size));
                    container = normalized.Value;
                }
                stage = "token-user";
                bool? anonymous = IsAnonymous(handle, out diagnostic);
                if (anonymous is null) return null;
                stage = "statistics-after";
                if (!GetStatistics(handle, 10, out var after, (uint)Marshal.SizeOf<Statistics>(), out size))
                    return Reject(out diagnostic, stage, "win32", Marshal.GetLastWin32Error());
                if (size != Marshal.SizeOf<Statistics>()) return Reject(out diagnostic, "statistics-after-length");
                if (before.TokenId != after.TokenId || before.ModifiedId != after.ModifiedId)
                    return Reject(out diagnostic, "token-changed");
                return Classify(after, thread, anonymous, restricted, container, out diagnostic);
            }
        }
        catch (Exception error) { return Reject(out diagnostic, stage, "managed", error.HResult); }
    }

    private static WindowsLdapContext? Reject(out QueryDiagnostic diagnostic, string stage, string kind = "rejected", int code = 0)
    { diagnostic = new(stage, kind, code); return null; }
    // The caller supplies a four-byte buffer. Accept only a fully written DWORD
    // boolean or a reported one-byte BOOLEAN with the upper sentinel untouched.
    // Unknown sizes/patterns are not interpreted as an unrestricted context.
    internal static uint? DecodeScalarFlag(uint value, uint returned)
    {
        if (returned == 4 && value <= 1) return value;
        if (returned == 1 && (value & 0xffffff00u) == (QuerySentinel & 0xffffff00u) && (value & 0xff) <= 1)
            return value & 0xff;
        return null;
    }
    internal static bool CanUseProcessToken(int error) => error == NoToken;

    internal static WindowsLdapContext? Classify(Statistics value, bool thread, bool? anonymous, uint restricted, uint container)
        => Classify(value, thread, anonymous, restricted, container, out _);
    internal static WindowsLdapContext? Classify(Statistics value, bool thread, bool? anonymous, uint restricted, uint container,
        out QueryDiagnostic diagnostic)
    {
        if (anonymous is null) return Reject(out diagnostic, "sid-unreadable");
        if (anonymous.Value) return Reject(out diagnostic, "anonymous");
        if (restricted != 0) return Reject(out diagnostic, "restricted");
        if (container != 0) return Reject(out diagnostic, "app-container-token");
        if (value.TokenId == 0) return Reject(out diagnostic, "token-id-unavailable");
        if (value.AuthenticationId == 0) return Reject(out diagnostic, "authentication-id-unavailable");
        if (value.ModifiedId == 0) return Reject(out diagnostic, "modified-id-unavailable");
        if (thread ? value.TokenType != 2 : value.TokenType != 1) return Reject(out diagnostic, "token-type");
        if (thread && value.ImpersonationLevel != 2) return Reject(out diagnostic, "impersonation-level");
        diagnostic = new("eligible", "none", 0);
        return new(value.TokenId, value.AuthenticationId, value.ModifiedId, value.TokenType,
            thread ? value.ImpersonationLevel : 0, thread);
    }

    private static bool? IsAnonymous(SafeAccessTokenHandle token, out QueryDiagnostic diagnostic)
    {
        diagnostic = new("token-user-length", "rejected", 0);
        bool success = GetBuffer(token, 1, IntPtr.Zero, 0, out uint required);
        int error = Marshal.GetLastWin32Error();
        if (success || error != InsufficientBuffer)
        { diagnostic = new("token-user-length", "win32", error); return null; }
        if (required < IntPtr.Size + sizeof(uint) || required > 4096) return null;
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!GetBuffer(token, 1, buffer, required, out uint actual))
            { diagnostic = new("token-user-read", "win32", Marshal.GetLastWin32Error()); return null; }
            diagnostic = new("token-user-read-length", "rejected", 0);
            if (actual > required || actual < IntPtr.Size + sizeof(uint)) return null;
            var value = ReadAnonymousSid(buffer, actual);
            diagnostic = new(value.HasValue ? "token-user-complete" : "sid-bounds", value.HasValue ? "none" : "rejected", 0);
            return value;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    // The caller owns this bounded TOKEN_USER allocation. Validate the native
    // embedded SID pointer before dereferencing; malformed output rejects reuse.
    internal static bool? ReadAnonymousSid(IntPtr buffer, uint actual)
    {
        if (buffer == IntPtr.Zero || actual < IntPtr.Size + sizeof(uint) || actual > 4096) return null;
        var sid = Marshal.ReadIntPtr(buffer);
        long offset = sid.ToInt64() - buffer.ToInt64();
        if (offset < IntPtr.Size + sizeof(uint) || offset > actual - 8) return null;
        int count = Marshal.ReadByte(sid, 1);
        int length = 8 + 4 * count;
        if (Marshal.ReadByte(sid) != 1 || count > 15 || offset + length > actual) return null;
        var bytes = new byte[length]; Marshal.Copy(sid, bytes, 0, length);
        return IsAnonymousSid(bytes);
    }

    internal static bool IsAnonymousSid(ReadOnlySpan<byte> sid) =>
        sid.SequenceEqual(new byte[] { 1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0 });

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool self, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetStatistics(SafeAccessTokenHandle token, int kind, out Statistics value, uint size, out uint returned);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFlag(SafeAccessTokenHandle token, int kind, ref uint value, uint size, ref uint returned);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBuffer(SafeAccessTokenHandle token, int kind, IntPtr value, uint size, out uint returned);
}
