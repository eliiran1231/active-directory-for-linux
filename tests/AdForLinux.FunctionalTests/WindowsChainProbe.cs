using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AdForLinux.FunctionalTests;

// Read-only chain infrastructure probe, never used by a WinLDAP connection.
// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
internal static class WindowsChainProbe
{
    // Per-call cache-only URL/revocation access, no AIA or root auto-update.
    // Check revocation except the root; no policy/trust errors are ignored.
    internal const uint Flags = 0x00000004 | 0x80000000 | 0x00000100 | 0x00002000 | 0x40000000;
    internal readonly record struct Result(bool ApiSucceeded, uint? NativeError, uint? TrustErrors, uint? TrustInfo);

    internal static Result Read(X509Certificate2 publicCertificate)
    {
        if (publicCertificate.HasPrivateKey) throw new InvalidOperationException("Probe requires a public certificate.");
        // Wincrypt default packing: full CERT_CHAIN_PARA is 96 bytes on x64,
        // 52 on x86. Check the pointer-bearing structures before calling native.
        var wide = IntPtr.Size == 8;
        if (Marshal.SizeOf<ChainParameters>() != (wide ? 96 : 52) ||
            Marshal.SizeOf<UsageMatch>() != (wide ? 24 : 12) ||
            Marshal.OffsetOf<ChainParameters>(nameof(ChainParameters.RequestedUsage)).ToInt32() != (wide ? 8 : 4) ||
            Marshal.OffsetOf<ChainParameters>(nameof(ChainParameters.CacheResync)).ToInt32() != (wide ? 72 : 40) ||
            Marshal.SizeOf<ChainHeader>() != 12)
            throw new InvalidOperationException("Unexpected native chain structure layout.");

        var parameters = new ChainParameters { Size = (uint)Marshal.SizeOf<ChainParameters>() };
        IntPtr context = IntPtr.Zero;
        // NULL engine = HCCE_CURRENT_USER; no additional store or custom trust.
        var succeeded = CertGetCertificateChain(IntPtr.Zero, publicCertificate.Handle, IntPtr.Zero,
            IntPtr.Zero, ref parameters, Flags, IntPtr.Zero, out context);
        // Capture immediately, before reading the context, cleanup or logging.
        var error = unchecked((uint)Marshal.GetLastPInvokeError());
        try
        {
            if (!succeeded) return new(false, error, null, null);
            if (context == IntPtr.Zero || unchecked((uint)Marshal.ReadInt32(context)) < 12)
                throw new InvalidOperationException("Native success did not return a valid chain header.");
            // Read only the documented cbSize + CERT_TRUST_STATUS prefix. Do
            // not traverse certificates, names, unrelated stores or machine data.
            var header = Marshal.PtrToStructure<ChainHeader>(context);
            return new(true, null, header.TrustErrors, header.TrustInfo);
        }
        finally
        {
            if (context != IntPtr.Zero) CertFreeCertificateChain(context);
            GC.KeepAlive(publicCertificate);
        }
    }

    // CERT_ENHKEY_USAGE / CERT_USAGE_MATCH / full CERT_CHAIN_PARA from wincrypt.h.
    [StructLayout(LayoutKind.Sequential)]
    private struct EnhancedUsage { public uint Count; public IntPtr Identifiers; }
    [StructLayout(LayoutKind.Sequential)]
    private struct UsageMatch { public uint Type; public EnhancedUsage Usage; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ChainParameters
    {
        public uint Size;
        public UsageMatch RequestedUsage;
        public UsageMatch RequestedIssuancePolicy;
        public uint UrlRetrievalTimeout;
        public int CheckRevocationFreshness; // Win32 BOOL is four bytes.
        public uint RevocationFreshness;
        public IntPtr CacheResync;
        public IntPtr StrongSignParameters;
        public uint StrongSignFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ChainHeader { public uint Size; public uint TrustErrors; public uint TrustInfo; }

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateChain(IntPtr engine, IntPtr certificate, IntPtr time,
        IntPtr additionalStore, ref ChainParameters parameters, uint flags, IntPtr reserved, out IntPtr context);
    [DllImport("crypt32.dll", ExactSpelling = true)]
    private static extern void CertFreeCertificateChain(IntPtr context);
}
