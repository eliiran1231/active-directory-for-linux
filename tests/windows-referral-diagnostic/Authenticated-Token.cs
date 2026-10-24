// Compile-only preparation. No static initialization invokes native code.
#nullable enable
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class AdflAuthenticatedToken : IDisposable
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUserW(string user, string domain, IntPtr password,
        int logonType, int provider, out SafeAccessTokenHandle token);
    private readonly object gate = new object();
    private SafeAccessTokenHandle? token;
    private readonly string expectedSid;
    private bool inScope;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeAccessTokenHandle source,
        IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, out int value, int size, out int returned);

    // The parent transfers a handle copy, not a password and not a new logon.
    public long CopyTo(System.Diagnostics.Process child)
    {
        lock (gate)
        {
            if (token == null) throw new ObjectDisposedException(nameof(AdflAuthenticatedToken));
            if (!DuplicateHandle(GetCurrentProcess(), token, child.Handle, out IntPtr copy, 0x000E, false, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error()); // QUERY | IMPERSONATE | DUPLICATE, non-inheritable.
            return copy.ToInt64(); // Meaningful only in that child; never log this value.
        }
    }

    public static AdflAuthenticatedToken Adopt(long ownedHandle, string expectedSid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (ownedHandle <= 0) throw new ArgumentException("Invalid transferred handle.");
        var owned = new SafeAccessTokenHandle(new IntPtr(ownedHandle));
        if (!GetTokenInformation(owned, 8, out int type, sizeof(int), out int returned) || returned != sizeof(int) || type != 1)
        { owned.Dispose(); throw new InvalidOperationException("Expected transferred primary token."); }
        return new AdflAuthenticatedToken(owned, expectedSid);
    }
    private AdflAuthenticatedToken(SafeAccessTokenHandle owned, string expectedSid)
    {
        token = owned; this.expectedSid = expectedSid;
        try { ValidateOwnedIdentity(); } catch { owned.Dispose(); throw; }
    }
    private void ValidateOwnedIdentity()
    {
        using var identity = new WindowsIdentity(token!.DangerousGetHandle());
        if (identity.User?.Value != expectedSid || identity.Groups?.Contains(new SecurityIdentifier("S-1-5-32-544")) == true)
            throw new InvalidOperationException("Expected non-administrator owned identity.");
    }

    // Acquire once per account, reuse across synchronous stages, dispose at end.
    public AdflAuthenticatedToken(string name, string expectedSid, SecureString password)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        this.expectedSid = expectedSid;
        IntPtr secret = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            // Interactive local logon; never NEW_CREDENTIALS, profiles or policy changes.
            if (!LogonUserW(name, ".", secret, 2, 0, out token))
            {
                int error = Marshal.GetLastWin32Error();
                token?.Dispose();
                throw new Win32Exception(error);
            }
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
        try { ValidateOwnedIdentity(); } catch { token?.Dispose(); throw; }
    }
    private static string CurrentSid()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            return identity.User?.Value ?? throw new InvalidOperationException("Identity SID unavailable.");
    }
    public void Run(Action operation)
    {
        lock (gate)
        {
            if (token == null) throw new ObjectDisposedException(nameof(AdflAuthenticatedToken));
            if (inScope) throw new InvalidOperationException("Nested scope unsupported.");
            string previous = CurrentSid();
            inScope = true;
            try
            {
                WindowsIdentity.RunImpersonated(token, () =>
                {
                    if (CurrentSid() != expectedSid) throw new InvalidOperationException("Authenticated identity mismatch.");
                    operation(); // No asynchronous work may outlive this scope.
                });
            }
            finally
            {
                inScope = false;
                // Failed restoration must never let cleanup run under the wrong user.
                try { if (CurrentSid() != previous) StopWithoutCrashReport(); }
                catch { StopWithoutCrashReport(); }
            }
        }
    }
    private static void StopWithoutCrashReport()
    {
        TerminateProcess(GetCurrentProcess(), 86); // Hard exit, not FailFast/WER/dump collection.
        Environment.Exit(86);
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (inScope) throw new InvalidOperationException("Cannot close token inside impersonation scope.");
            token?.Dispose();
            token = null;
        }
    }
}
