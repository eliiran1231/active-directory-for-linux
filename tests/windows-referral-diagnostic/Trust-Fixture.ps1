param([switch]$Cleanup, [switch]$SetupWorker)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only a disposable GitHub-hosted Windows runner is permitted.'
}
$directory = Join-Path $env:RUNNER_TEMP 'adfl-referral-trust-cryptui-once'
$manifest = Join-Path $directory 'thumbprint.txt'
$pfx = Join-Path $directory 'loopback.pfx'
$stageFile = Join-Path $directory 'stage.txt'
$verified = Join-Path $directory 'verified.txt'
function Stage([string]$Name) {
    [System.IO.File]::WriteAllText($stageFile, $Name)
    Write-Host "STAGE $Name"
}
function Remove-Fixture {
    if (Test-Path $manifest) {
        $thumbprint = (Get-Content -Raw $manifest).Trim()
        if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw 'Invalid exact thumbprint manifest.' }
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        try {
            $store.Open('ReadWrite')
            $matches = $store.Certificates.Find('FindByThumbprint', $thumbprint, $false)
            Write-Host "CLEANUP exact thumbprint $thumbprint; matches=$($matches.Count)"
            foreach ($certificate in $matches) { $store.Remove($certificate) }
        } finally { $store.Dispose() }
        # Reopen the store to verify removal independently of the mutation handle.
        $check = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        try {
            $check.Open('ReadOnly')
            if ($check.Certificates.Find('FindByThumbprint', $thumbprint, $false).Count -ne 0) {
                throw "Removal verification failed for $thumbprint"
            }
            Write-Host "Verified absent from CurrentUser Root: $thumbprint"
        } finally { $check.Dispose() }
    } else { Write-Host 'CLEANUP no thumbprint manifest; import cannot have been reached.' }
    if (Test-Path $pfx) { Remove-Item -LiteralPath $pfx -Force }
    if (Test-Path $pfx) { throw 'Fixture PFX removal failed.' }
    Write-Host 'Verified fixture PFX absent.'
    Remove-Item Env:ADFL_REFERRAL_TEST_PFX -ErrorAction SilentlyContinue
}
if ($Cleanup) { Remove-Fixture; exit 0 }
if ($SetupWorker) {
    $key = $null; $generated = $null; $public = $null; $store = $null; $chain = $null
    try {
        Stage 'interop-compile:start'
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
public static class FixtureCryptUI {
    [StructLayout(LayoutKind.Sequential)]
    private struct ImportSource {
        public uint Size;
        public uint SubjectChoice;
        public IntPtr CertificateContext;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
    }
    [DllImport("cryptui.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUIWizImport(uint flags, IntPtr parent,
        IntPtr title, ref ImportSource source, IntPtr destination);
    public static void ImportPublic(X509Certificate2 certificate, X509Store store) {
        if (certificate.HasPrivateKey) throw new InvalidOperationException("Public certificate required.");
        var source = new ImportSource {
            Size = (uint)Marshal.SizeOf<ImportSource>(),
            SubjectChoice = 2, // CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT
            CertificateContext = certificate.Handle,
            Password = string.Empty
        };
        // CRYPTUI_WIZ_NO_UI; destination is the explicitly opened CurrentUser Root.
        bool imported = CryptUIWizImport(0x0001, IntPtr.Zero, IntPtr.Zero, ref source, store.StoreHandle);
        int error = Marshal.GetLastWin32Error();
        GC.KeepAlive(certificate);
        GC.KeepAlive(store);
        if (!imported) throw new Win32Exception(error, "CryptUIWizImport failed.");
    }
}
'@
        Stage 'interop-compile:done'
        Stage 'generate:start'
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=ADFL disposable loopback TEST', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $names = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $names.AddIpAddress([System.Net.IPAddress]::Loopback)
        $names.AddDnsName('localhost')
        $request.CertificateExtensions.Add($names.Build())
        $oids = [System.Security.Cryptography.OidCollection]::new()
        $oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
        $generated = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
        Stage 'generate:done'
        Stage 'export-public:start'
        $publicBytes = $generated.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($publicBytes)
        if ($public.HasPrivateKey) { throw 'Trust-store certificate must be public only.' }
        Stage 'export-public:done'
        Stage 'manifest-write:start'
        [System.IO.File]::WriteAllText($manifest, $public.Thumbprint)
        Write-Host "TEST public thumbprint: $($public.Thumbprint)"
        Stage 'manifest-write:done'
        Stage 'export-pfx:start'
        $pfxBytes = $generated.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        Stage 'export-pfx:done'
        Stage 'pfx-write:start'
        [System.IO.File]::WriteAllBytes($pfx, $pfxBytes)
        [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
        Stage 'pfx-write:done'
        Stage 'store-open:start'
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        $store.Open('ReadWrite')
        if ($store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false).Count -ne 0) { throw 'Certificate already exists.' }
        Stage 'store-open:done'
        Stage 'import:start'
        [FixtureCryptUI]::ImportPublic($public, $store)
        Stage 'import:done'
        $store.Dispose(); $store = $null
        Stage 'verify-trust:start'
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        $store.Open('ReadOnly')
        $matches = $store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false)
        if ($matches.Count -ne 1 -or $matches[0].HasPrivateKey) { throw 'Exact public certificate not found in CurrentUser Root.' }
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        if (!$chain.Build($public)) { throw 'Default certificate chain validation failed.' }
        if ($chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint -ne $public.Thumbprint) {
            throw 'Unexpected trust anchor.'
        }
        [System.IO.File]::WriteAllText($verified, $public.Thumbprint)
        Stage 'verify-trust:done'
    } finally {
        foreach ($resource in @($chain, $store, $public, $generated, $key)) {
            if ($null -ne $resource) { $resource.Dispose() }
        }
    }
    exit 0
}
function Run-Bounded([string]$Executable, [string[]]$Arguments, [int]$Seconds) {
    $info = [System.Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $started = $false
    try {
        if (!$process.Start()) { throw 'Child process did not start.' }
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = !$process.WaitForExit($Seconds * 1000)
        if ($timedOut) {
            $process.Kill($true)
            if (!$process.WaitForExit(10000)) { throw 'Child process termination not confirmed.' }
        }
        if (![System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) {
            Write-Host "OUTPUT-DRAIN TIMEOUT; last stage=$(Get-Content -Raw $stageFile)"
            return 125
        }
        Write-Host $stdout.GetAwaiter().GetResult()
        Write-Host $stderr.GetAwaiter().GetResult()
        if ($timedOut) {
            Write-Host "TIMEOUT after $Seconds seconds; last stage=$(Get-Content -Raw $stageFile)"
            return 124
        }
        return $process.ExitCode
    } finally {
        try {
            if ($started -and !$process.HasExited) {
                $process.Kill($true)
                if (!$process.WaitForExit(10000)) { throw 'Child termination not confirmed during cleanup.' }
            }
        } finally { $process.Dispose() }
    }
}
if (Test-Path $directory) { throw 'Diagnostic already initialized; refusing another setup.' }
New-Item -ItemType Directory -Path $directory | Out-Null
try {
    Stage 'setup-worker:start'
    $code = Run-Bounded (Get-Process -Id $PID).Path @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath, '-SetupWorker') 60
    if ($code -ne 0) { throw "Setup failed: exit=$code; stage=$(Get-Content -Raw $stageFile). Tests not started." }
    if (!(Test-Path $verified) -or (Get-Content -Raw $verified) -ne (Get-Content -Raw $manifest)) {
        throw 'Trust verification marker missing or mismatched. Tests not started.'
    }
    Write-Host "Trust verified before tests: $(Get-Content -Raw $verified)"
    $env:ADFL_REFERRAL_TEST_PFX = $pfx
    $failed = $false
    foreach ($framework in @('net8.0', 'net10.0')) {
        Stage "test-${framework}:start"
        $code = Run-Bounded (Get-Command dotnet).Source @('test', 'tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj', '--no-build', '--no-restore', '--configuration', 'Release', '--framework', $framework, '--filter', 'FullyQualifiedName~AdForLinux.FunctionalTests.WindowsBasicReferralTests.', '--logger', 'console;verbosity=detailed', '--logger', "trx;LogFileName=trusted-$framework.trx", '--results-directory', 'artifacts') 180
        Write-Host "RESULT $framework exit=$code"
        if ($code -ne 0) { $failed = $true }
        Stage "test-${framework}:done"
    }
    if ($failed) { throw 'Native diagnostic assertions failed; inspect both runtime results.' }
} finally { Remove-Fixture }
