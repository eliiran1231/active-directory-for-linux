param([switch]$Cleanup, [switch]$SetupWorker)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only a disposable GitHub-hosted Windows runner is permitted.'
}
$directory = Join-Path $env:RUNNER_TEMP 'adfl-referral-machine-trust-20261022-once'
$manifest = Join-Path $directory 'thumbprint.txt'
$pfx = Join-Path $directory 'loopback.pfx'
$stageFile = Join-Path $directory 'stage.txt'
$verified = Join-Path $directory 'verified.txt'
$workerRecord = Join-Path $directory 'worker.json'
function Stop-OwnedWorker {
    if (!(Test-Path $workerRecord)) { return }
    $record = Get-Content -Raw $workerRecord | ConvertFrom-Json
    $worker = $null
    try { $worker = [System.Diagnostics.Process]::GetProcessById([int]$record.ProcessId) }
    catch [System.ArgumentException] { return } # Already exited.
    try {
        if ($worker.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.StartTicks) { return } # PID reused.
        if (!$worker.HasExited) {
            $worker.Kill($true)
            if (!$worker.WaitForExit(10000)) { throw 'Owned worker termination not confirmed; cleanup must not race it.' }
        }
        Write-Host 'Owned worker stopped before cleanup.'
    } finally { $worker.Dispose() }
}
function Stage([string]$Name) {
    [System.IO.File]::WriteAllText($stageFile, $Name)
    Write-Host "STAGE $Name"
}
function Remove-Fixture {
    Stop-OwnedWorker
    try {
        if (Test-Path $manifest) {
            $thumbprint = (Get-Content -Raw $manifest).Trim()
            if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw 'Invalid exact thumbprint manifest.' }
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
            try {
                $store.Open('ReadWrite')
                $matches = $store.Certificates.Find('FindByThumbprint', $thumbprint, $false)
                Write-Host "CLEANUP owned exact thumbprint $thumbprint; matches=$($matches.Count)"
                foreach ($certificate in $matches) {
                    if ($certificate.HasPrivateKey) { throw 'Unexpected private-key entry; refusing to remove it.' }
                    $store.Remove($certificate)
                }
            } finally { $store.Dispose() }
            $check = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
            try {
                $check.Open('ReadOnly')
                if ($check.Certificates.Find('FindByThumbprint', $thumbprint, $false).Count -ne 0) {
                    throw "Removal verification failed for $thumbprint"
                }
                Write-Host "Verified absent from LocalMachine Root: $thumbprint"
            } finally { $check.Dispose() }
        } else { Write-Host 'CLEANUP no ownership manifest; no certificate removal authorized or needed.' }
    } finally {
        if (Test-Path $pfx) { Remove-Item -LiteralPath $pfx -Force }
        if (Test-Path $pfx) { throw 'Fixture PFX removal failed.' }
        Write-Host 'Verified fixture PFX absent.'
        Remove-Item Env:ADFL_REFERRAL_TEST_PFX -ErrorAction SilentlyContinue
    }
}
if ($Cleanup) { Remove-Fixture; exit 0 }
if ($SetupWorker) {
    $key = $null; $generated = $null; $public = $null; $store = $null; $chain = $null
    try {
        # Parent records ownership before this worker can reach generation/import.
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while (!(Test-Path $workerRecord) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
        $record = Get-Content -Raw $workerRecord | ConvertFrom-Json
        if ([int]$record.ProcessId -ne $PID) { throw 'Setup worker ownership not established.' }
        Stage 'generate:start'
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            ('CN=ADFL disposable machine TEST ' + [Guid]::NewGuid().ToString('N')), $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
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
        Stage 'export-pfx:start'
        $pfxBytes = $generated.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        Stage 'export-pfx:done'
        Stage 'pfx-write:start'
        [System.IO.File]::WriteAllBytes($pfx, $pfxBytes)
        [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
        Stage 'pfx-write:done'
        Stage 'store-open:start'
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        $store.Open('ReadWrite')
        if ($store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false).Count -ne 0) { throw 'Certificate already exists.' }
        Stage 'store-open:done'
        # Ownership is recorded only after confirming this exact unique certificate
        # is absent. A preexisting match aborts without an ownership manifest.
        Stage 'manifest-write:start'
        [System.IO.File]::WriteAllText("$manifest.tmp", $public.Thumbprint)
        [System.IO.File]::Move("$manifest.tmp", $manifest)
        Write-Host "TEST public thumbprint: $($public.Thumbprint)"
        Stage 'manifest-write:done'
        Stage 'import:start'
        $store.Add($public)
        Stage 'import:done'
        $store.Dispose(); $store = $null
        Stage 'verify-trust:start'
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        $store.Open('ReadOnly')
        $matches = $store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false)
        if ($matches.Count -ne 1 -or $matches[0].HasPrivateKey) { throw 'Exact public certificate not found in LocalMachine Root.' }
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
        [System.IO.File]::WriteAllText("$workerRecord.tmp", (@{
            ProcessId = $process.Id; StartTicks = $process.StartTime.ToUniversalTime().Ticks.ToString()
        } | ConvertTo-Json -Compress))
        [System.IO.File]::Move("$workerRecord.tmp", $workerRecord, $true)
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
        Stage "trust-controls-${framework}:start"
        $trustResults = Join-Path 'artifacts' "trust-controls-$framework.trx"
        if (Test-Path $trustResults) { throw 'Trust-control results already exist; refusing to reuse them.' }
        $code = Run-Bounded (Get-Command dotnet).Source @('test', 'tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj', '--no-build', '--no-restore', '--configuration', 'Release', '--framework', $framework, '--filter', 'FullyQualifiedName~AdForLinux.FunctionalTests.WindowsBasicReferralTests.Diagnostic_normal_trust_across_windows_identities', '--logger', 'console;verbosity=detailed', '--logger', "trx;LogFileName=trust-controls-$framework.trx", '--results-directory', 'artifacts') 120
        Write-Host "TRUST-CONTROLS $framework exit=$code"
        $trustPassed = $false
        if ($code -eq 0 -and (Test-Path $trustResults)) {
            [xml]$result = Get-Content -Raw $trustResults
            $counts = $result.TestRun.ResultSummary.Counters
            $trustPassed = $counts.total -eq '2' -and $counts.executed -eq '2' -and $counts.passed -eq '2' -and $counts.failed -eq '0' -and $counts.notExecuted -eq '0'
        }
        if (!$trustPassed) {
            $failed = $true
            Write-Host "Skipping native referrals for $framework: normal trust under both identities not verified."
            continue
        }
        Write-Host "Normal trust verified in original and anonymous identities for $framework; exactly two controls passed."
        Stage "native-referrals-${framework}:start"
        $code = Run-Bounded (Get-Command dotnet).Source @('test', 'tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj', '--no-build', '--no-restore', '--configuration', 'Release', '--framework', $framework, '--filter', 'FullyQualifiedName~AdForLinux.FunctionalTests.WindowsBasicReferralTests.Native_|FullyQualifiedName~AdForLinux.FunctionalTests.WindowsBasicReferralTests.Diagnostic_transport_and_name_variants', '--logger', 'console;verbosity=detailed', '--logger', "trx;LogFileName=machine-trusted-$framework.trx", '--results-directory', 'artifacts') 180
        Write-Host "NATIVE-RESULT $framework exit=$code"
        if ($code -ne 0) { $failed = $true }
        $nativeResults = Join-Path 'artifacts' "machine-trusted-$framework.trx"
        if (Test-Path $nativeResults) {
            [xml]$result = Get-Content -Raw $nativeResults
            $counts = $result.TestRun.ResultSummary.Counters
            Write-Host "NATIVE-COUNTS $framework total=$($counts.total) executed=$($counts.executed) passed=$($counts.passed) failed=$($counts.failed) skipped=$($counts.notExecuted)"
            if ($counts.total -ne '6' -or $counts.executed -ne '6' -or $counts.passed -ne '6') { $failed = $true }
        } else { $failed = $true }
        Stage "native-referrals-${framework}:done"
    }
    if ($failed) { throw 'Native diagnostic assertions failed; inspect both runtime results.' }
} finally { Remove-Fixture }
