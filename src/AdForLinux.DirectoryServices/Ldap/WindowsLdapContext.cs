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
    private const int NoToken = 1008, InsufficientBuffer = 122;
    [StructLayout(LayoutKind.Sequential)]
    internal struct Statistics
    {
        internal ulong TokenId, AuthenticationId;
        internal long Expiration;
        internal uint TokenType, ImpersonationLevel, DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
        internal ulong ModifiedId;
    }

    internal static WindowsLdapContext? Capture()
    {
        if (OfflineTestGuard.Enabled || !OperatingSystem.IsWindows()) return null;
        try
        {
            bool thread = true;
            if (!OpenThreadToken(new IntPtr(-2), TokenQuery, true, out var handle))
            {
                int error = Marshal.GetLastWin32Error();
                handle?.Dispose();
                if (!CanUseProcessToken(error)) return null; // Anonymous/access denied is NOT process identity.
                thread = false;
                if (!OpenProcessToken(new IntPtr(-1), TokenQuery, out handle))
                { handle?.Dispose(); return null; }
            }
            using (handle)
            {
                if (!GetStatistics(handle, 10, out var before, (uint)Marshal.SizeOf<Statistics>(), out var size) ||
                    size != Marshal.SizeOf<Statistics>()) return null;
                if (!GetFlag(handle, 21, out uint restricted, sizeof(uint), out size) || size != sizeof(uint) ||
                    !GetFlag(handle, 29, out uint container, sizeof(uint), out size) || size != sizeof(uint)) return null;
                bool? anonymous = IsAnonymous(handle);
                // Auxiliary queries must not straddle a persistent token modification.
                if (!GetStatistics(handle, 10, out var after, (uint)Marshal.SizeOf<Statistics>(), out size) ||
                    size != Marshal.SizeOf<Statistics>() || before.TokenId != after.TokenId ||
                    before.ModifiedId != after.ModifiedId) return null;
                return Classify(after, thread, anonymous, restricted, container);
            }
        }
        catch { return null; } // Query failure rejects reuse, not the caller's fresh LDAP operation.
    }

    internal static bool CanUseProcessToken(int error) => error == NoToken;

    internal static WindowsLdapContext? Classify(Statistics value, bool thread, bool? anonymous, uint restricted, uint container)
    {
        if (anonymous != false || restricted != 0 || container != 0 || value.TokenId == 0 ||
            value.AuthenticationId == 0 || value.ModifiedId == 0) return null;
        if (thread ? value.TokenType != 2 || value.ImpersonationLevel != 2 : value.TokenType != 1) return null;
        return new(value.TokenId, value.AuthenticationId, value.ModifiedId, value.TokenType,
            thread ? value.ImpersonationLevel : 0, thread);
    }

    private static bool? IsAnonymous(SafeAccessTokenHandle token)
    {
        if (GetBuffer(token, 1, IntPtr.Zero, 0, out uint required) ||
            Marshal.GetLastWin32Error() != InsufficientBuffer || required < IntPtr.Size + sizeof(uint) || required > 4096)
            return null;
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!GetBuffer(token, 1, buffer, required, out uint actual) || actual > required || actual < IntPtr.Size + sizeof(uint))
                return null;
            return ReadAnonymousSid(buffer, actual);
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
    private static extern bool GetFlag(SafeAccessTokenHandle token, int kind, out uint value, uint size, out uint returned);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBuffer(SafeAccessTokenHandle token, int kind, IntPtr value, uint size, out uint returned);
}
