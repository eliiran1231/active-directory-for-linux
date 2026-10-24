param(
    [ValidateSet('Preflight', 'Supervisor', 'Coordinator', 'Cleanup', 'E2ESupervisor', 'E2ECoordinator', 'E2ECleanup')][string]$Mode = 'Preflight',
    [string]$RunId,
    [ValidateSet('Success', 'SetupEarlyExit', 'SecondCreateFailure', 'SetupTimeout', 'RuntimeTimeout', 'PartialHandoff', 'MalformedOutput', 'OutputOverflow', 'EarlyExit', 'TruncatedFrame', 'CleanupFailures')][string]$E2ECase = 'Success'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Fixture-Core.ps1')
$testOnly = $Mode.StartsWith('E2E', [StringComparison]::OrdinalIgnoreCase)
if (!$testOnly -and $E2ECase -ne 'Success') { throw 'Fault injection requires explicit E2E mode.' }
if ($testOnly) { . (Join-Path $PSScriptRoot 'Authenticated-E2E-Adapters.ps1') }
else { . (Join-Path $PSScriptRoot 'Authenticated-Windows-Adapters.ps1') }
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
. (Join-Path $PSScriptRoot 'Certificate-Material.ps1')
. (Join-Path $PSScriptRoot 'Owned-Key.ps1')
if ($Mode -eq 'Preflight') { Write-Host 'No execution. Run Test-AuthenticatedFixture.ps1 for pure preflight.'; return }
if (!$IsWindows -or ![Environment]::Is64BitProcess -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $RunId -cnotmatch '^[0-9a-f]{32}$') {
    throw 'Disposable hosted Windows x64 and unique run ID required.'
}
if (!$testOnly) { Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Token.cs') }
elseif (('AdflAuthenticatedToken' -as [type]) -or (Get-Command New-AuthenticatedWindowsAccountOperations -ErrorAction SilentlyContinue)) {
    throw 'Real identity adapter must not be loaded in E2E mode.'
}
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Process.cs')
$root = Get-DiagnosticRoot $env:LOCALAPPDATA $RunId
$ownerPath = Join-Path $root 'owner.json'
$accountPath = Join-Path $root 'accounts.json'
$certificatePath = Join-Path $root 'certificate.json'
$pfxPath = Join-Path $root 'loopback.pfx'
$keyPath = Join-Path $root 'provider-key.json'
$publicPath = Join-Path $root 'loopback.cer'
$stagePath = Join-Path $root 'stage.txt'
$fixtureScriptPath = $PSCommandPath

function Stage([string]$Name) {
    if ($Name -notin @('accounts', 'logons', 'provider-key-create', 'certificate-generate', 'certificate-export', 'pfx-write',
        'certificate-import', 'certificate-verify', 'managed-chain', 'setup-ready', 'net8', 'net10', 'complete')) { throw 'Unknown stage.' }
    [IO.File]::WriteAllText($stagePath, $Name)
    [IO.File]::AppendAllText((Join-Path $root 'stages.txt'), "$Name`n")
}
function Read-Owner {
    Assert-DiagnosticNoReparsePath $root
    $record = Get-Content -Raw -LiteralPath $ownerPath | ConvertFrom-Json -AsHashtable
    if ($record.Version -ne 1 -or $record.RunId -cne $RunId -or
        $record.JobName -cne "Local\adfl-auth-$RunId" -or $record.JobOwned -isnot [bool] -or $record.TestOnly -isnot [bool] -or $record.TestOnly -ne $testOnly) { throw 'Invalid job ownership.' }
    return $record
}
function Remove-OwnedCertificate {
    if ($testOnly) { Remove-E2ECertificate; return }
    if (!(Test-Path -LiteralPath $certificatePath)) { return }
    $record = Get-Content -Raw -LiteralPath $certificatePath | ConvertFrom-Json -AsHashtable
    if ($record.Version -ne 1 -or $record.RunId -cne $RunId -or $record.Thumbprint -cnotmatch '^[0-9A-F]{40}$' -or
        $record.DerHash -cnotmatch '^[0-9A-F]{64}$') { throw 'Invalid certificate ownership.' }
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    try {
        $store.Open('ReadWrite')
        foreach ($certificate in $store.Certificates.Find('FindByThumbprint', $record.Thumbprint, $false)) {
            $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData))
            if ($certificate.HasPrivateKey -or $hash -cne $record.DerHash) { throw 'Certificate ownership mismatch.' }
            $store.Remove($certificate)
        }
    } finally { $store.Dispose() }
    $verify = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    try {
        $verify.Open('ReadOnly')
        if ($verify.Certificates.Find('FindByThumbprint', $record.Thumbprint, $false).Count -ne 0) { throw 'Certificate remains.' }
    } finally { $verify.Dispose() }
    Write-Host "CLEANUP verified absent certificate $($record.Thumbprint)"
}
function Remove-Fixture {
    $owner = Read-Owner
    if ($owner.JobOwned) { [AdflProcessJob]::StopRecorded($owner.JobName) }
    $state = $null
    try { $state = Read-AuthenticatedManifest $accountPath } catch { } # Independently owned cleanup must still run.
    $operations = if ($testOnly) { New-E2EAccountOperations } else { New-AuthenticatedWindowsAccountOperations ([Collections.Generic.Dictionary[string, Security.SecureString]]::new()) }
    $operations.StopWorker = { } # Named job already terminated and verified empty above.
    $operations.Certificate = { Remove-OwnedCertificate }
    $operations.ProviderKey = {
        if ($testOnly) { return }
        if (!(Test-Path -LiteralPath $keyPath)) { Write-Host 'CLEANUP provider key not created (no manifest)'; return }
        $record = Get-Content -Raw -LiteralPath $keyPath | ConvertFrom-Json -AsHashtable
        Remove-DiagnosticOwnedKey $record $RunId (New-DiagnosticKeyOperations $keyPath)
        Write-Host 'CLEANUP verified owned provider key absent'
    }
    $operations.Pfx = {
        if (Test-Path -LiteralPath $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
        if (Test-Path -LiteralPath $pfxPath) { throw 'PFX remains.' }
        Write-Host 'CLEANUP verified PFX absent'
    }
    $failures = Remove-AuthenticatedObjects $state $operations
    foreach ($failure in $failures) { Write-Host "CLEANUP failed $failure" }
    if ($failures.Count -ne 0) { throw 'Cleanup incomplete; sanitized identifiers above.' }
    Write-Host 'CLEANUP all owned objects verified absent'
}
function New-FixtureCertificate {
    if ($testOnly) { return New-E2ECertificate }
    $operations = New-DiagnosticKeyOperations $keyPath
    $record = @{ Version = 1; RunId = $RunId; Name = "adfl-auth-$RunId"; Provider = $DiagnosticKeyProvider;
        Sid = (& $operations.CurrentSid); State = 'creating'; PublicHash = $null }
    Stage 'provider-key-create'
    $ownedKey = New-DiagnosticOwnedKey $record $operations
    $material = $null
    try {
        $material = New-DiagnosticCertificateMaterial $RunId { param($name) Stage $name } $ownedKey
        $public = $material.Public
        [IO.File]::WriteAllBytes($publicPath, $public.RawData) # Public DER only; no PFX or private-key export.
        $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        try {
            $store.Open('ReadWrite')
            if ($store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false).Count -ne 0) { throw 'Certificate preexists; no ownership recorded.' }
            Save-DiagnosticJson @{ Version = 1; RunId = $RunId; Thumbprint = $public.Thumbprint;
                DerHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($public.RawData)) } $certificatePath
            Stage 'certificate-import'
            $store.Add($public)
        } finally { $store.Dispose() }
        Stage 'certificate-verify'
        $verify = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        try {
            $verify.Open('ReadOnly')
            $matches = $verify.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false)
            if ($matches.Count -ne 1 -or $matches[0].HasPrivateKey -or
                [Convert]::ToHexString($matches[0].RawData) -cne [Convert]::ToHexString($public.RawData)) { throw 'Exact public certificate presence not verified.' }
        } finally { $verify.Dispose() }
        Stage 'managed-chain'
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $managed = 'failed'
        try { if ($chain.Build($public)) { $managed = 'passed' } } catch { $managed = 'error' }
        finally { $chain.Dispose() }
        Save-DiagnosticJson @{ OriginalManagedChain = $managed; Interpretation = 'non-gating-native-controls-required' } (Join-Path $root 'chain.json')
        return $public.Thumbprint
    } finally { Remove-DiagnosticCertificateMaterial $material; $ownedKey.Dispose() }
}

if ($Mode -in @('Cleanup', 'E2ECleanup')) {
    try { Remove-Fixture; exit 0 } catch { Write-Host 'Independent cleanup incomplete; no raw exception output.'; exit 2 }
}
if ($Mode -in @('Coordinator', 'E2ECoordinator')) {
    $credentials = [Collections.Generic.Dictionary[string, Security.SecureString]]::new()
    $tokens = [Collections.Generic.List[object]]::new()
    try {
        # No mutations before the supervisor assigns the process tree to its job.
        if ([AdflPrivateFrame]::Read([Console]::OpenStandardInput()) -cne $RunId) { throw 'Invalid release barrier.' }
        $owner = Read-Owner
        if (!$owner.JobOwned) { throw 'Job ownership not established.' }
        [AdflProcessJob]::VerifyCurrentMembership($owner.JobName)
        $state = Read-AuthenticatedManifest $accountPath
        Stage 'accounts'
        if ($testOnly -and $E2ECase -eq 'SetupEarlyExit') {
            [IO.File]::WriteAllText((Join-Path $root 'e2e-fault.txt'), $E2ECase); exit 3
        }
        $accountOperations = if ($testOnly) { New-E2EAccountOperations } else { New-AuthenticatedWindowsAccountOperations $credentials }
        Initialize-AuthenticatedAccounts $state { Save-AuthenticatedManifest $state $accountPath } $accountOperations
        Stage 'logons'
        foreach ($account in $state.Accounts) {
            if ($testOnly) { $tokens.Add((New-E2EToken ($tokens.Count + 1))) }
            else { $tokens.Add([AdflAuthenticatedToken]::new($account.Name, $account.Sid, $credentials[$account.Name])) }
        }
        foreach ($secret in $credentials.Values) { $secret.Dispose() }; $credentials.Clear()
        $thumbprint = New-FixtureCertificate
        Stage 'setup-ready'
        Save-DiagnosticJson @{ RunId = $RunId; Ready = $true } (Join-Path $root 'ready.json')
        $allPassed = $true
        foreach ($framework in @('net8.0', 'net10.0')) {
            Stage $(if ($framework -eq 'net8.0') { 'net8' } else { 'net10' })
            try {
                $result = Invoke-DiagnosticRuntime @{
                    Start = {
                        param($context)
                        $context.Job = [AdflProcessJob]::new('Local\adfl-auth-' + [Guid]::NewGuid().ToString('N'))
                        $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
                        $workerArguments = if ($testOnly) { @($binary, '--setup-e2e', $root) } else { @($binary) }
                        $context.Process = Start-DiagnosticProcess 'dotnet' $workerArguments
                        $context.Capture = [AdflBoundedCapture]::new($context.Process)
                    }
                    Assign = { param($context) $context.Job.Assign($context.Process) }
                    CopyA = { param($context) $tokens[0].CopyTo($context.Process).ToString([Globalization.CultureInfo]::InvariantCulture) }
                    CopyB = { param($context) $tokens[1].CopyTo($context.Process).ToString([Globalization.CultureInfo]::InvariantCulture) }
                    Release = {
                        param($context, $first, $second)
                        $envelope = @{ Version = 1; AHandle = $first; BHandle = $second; ASid = $state.Accounts[0].Sid;
                            BSid = $state.Accounts[1].Sid; Root = $root; Thumbprint = $thumbprint; TestOnly = $testOnly }
                        if ($testOnly -and $E2ECase -eq 'TruncatedFrame') {
                            $startup = [Diagnostics.Stopwatch]::StartNew()
                            while (!(Test-Path -LiteralPath (Join-Path $root "e2e-worker-ready-$framework.txt"))) {
                                if ($context.Process.HasExited -or $startup.ElapsedMilliseconds -gt 15000) { throw 'E2E worker did not reach frame read.' }
                                Start-Sleep -Milliseconds 50
                            }
                            $context.Process.StandardInput.BaseStream.Write([BitConverter]::GetBytes(100)); $context.Process.StandardInput.Close()
                            [IO.File]::WriteAllText((Join-Path $root 'e2e-fault.txt'), $E2ECase); return
                        }
                        [AdflPrivateFrame]::Write($context.Process.StandardInput.BaseStream, ($envelope | ConvertTo-Json -Compress))
                        $context.Process.StandardInput.Close()
                    }
                    Wait = {
                        param($context, $milliseconds)
                        if ($testOnly -and $E2ECase -eq 'RuntimeTimeout') {
                            $startup = [Diagnostics.Stopwatch]::StartNew()
                            while (!(Test-Path -LiteralPath (Join-Path $root 'e2e-fault.txt'))) {
                                if ($context.Process.HasExited -or $startup.ElapsedMilliseconds -gt 15000) { throw 'E2E descendant startup failed.' }
                                Start-Sleep -Milliseconds 50
                            }
                            $milliseconds = 1000 # Injected deadline only after the fake worker starts its real descendant.
                        }
                        if (!$context.Process.WaitForExit($milliseconds)) { throw 'Runtime timeout.' }
                    }
                    Read = {
                        param($context)
                        if ($context.Process.ExitCode -notin @(0, 1)) { throw 'Worker failed before valid results.' }
                        if ($testOnly) {
                            $synthetic = $context.Capture.Result() | ConvertFrom-Json -AsHashtable
                            if (($synthetic.Keys | Sort-Object) -join ',' -cne 'Observations,TestOnly' -or $synthetic.TestOnly -isnot [bool] -or !$synthetic.TestOnly) { throw 'E2E output discriminator missing.' }
                            ConvertTo-DiagnosticResult ($synthetic.Observations | ConvertTo-Json -Depth 8 -Compress)
                        } else { ConvertTo-DiagnosticResult ($context.Capture.Result()) }
                    }
                    StopAndVerify = {
                        param($context)
                        if ($context.Job) { $context.Job.StopAndVerify() } # Includes all descendants before next runtime.
                        if ($context.Process -and !$context.Process.HasExited) {
                            $context.Process.Kill($true)
                            if (!$context.Process.WaitForExit(10000)) { throw 'Unassigned runtime worker remains.' }
                        }
                    }
                    Dispose = {
                        param($context)
                        if ($context.Process) { $context.Process.Dispose() }
                        if ($context.Job) { $context.Job.Dispose() }
                    }
                }
                $resultName = if ($testOnly) { "$framework-e2e-results.json" } else { "$framework-results.json" }
                Save-DiagnosticJson $result (Join-Path $root $resultName)
                if (@($result.Values | Where-Object Status -NE 'passed').Count -ne 0) { $allPassed = $false }
            } catch {
                Save-DiagnosticJson @{ Worker = 'failed'; RawOutput = 'withheld' } (Join-Path $root "$framework-failure.json")
                throw # Any infrastructure/termination failure aborts; supervisor verifies the whole job empty.
            }
        }
        Stage 'complete'
        if ($allPassed) { exit 0 } else { exit 1 }
    } catch {
        Save-DiagnosticJson @{ NativeErrorCode = (Get-DiagnosticNativeErrorCode $_); Status = 'failed' } (Join-Path $root 'coordinator-failure.json')
        exit 2
    }
    finally {
        foreach ($token in $tokens) { $token.Dispose() }
        foreach ($secret in $credentials.Values) { $secret.Dispose() }; $credentials.Clear()
    }
}

# Supervisor creates no credentials and never impersonates. Both builds must exist.
foreach ($framework in @('net8.0', 'net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    if (!(Test-Path $binary)) { throw 'Build both workers before setup.' }
    $preflight = Start-DiagnosticProcess 'dotnet' @($binary, '--self-test')
    try {
        $capture = [AdflBoundedCapture]::new($preflight)
        if (!$preflight.WaitForExit(30000) -or $preflight.ExitCode -ne 0) { throw 'Pure runtime preflight failed; no setup permitted.' }
        if ($capture.Result().Trim() -cne 'Pure worker stage, bounded-frame and interop-layout checks passed. No native operations executed.') { throw 'Unexpected preflight output withheld.' }
    } finally {
        if (!$preflight.HasExited) { $preflight.Kill($true); $null = $preflight.WaitForExit(10000) }
        $preflight.Dispose()
    }
}
if (Test-Path -LiteralPath $root) { throw 'Run directory preexists; no setup or cleanup authorized.' }
$parent = [IO.Path]::GetDirectoryName($root)
Assert-DiagnosticNoReparsePath $parent
Assert-DiagnosticDirectoryPrivate $parent
$parentAclBefore = if ($testOnly) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Get-Acl -LiteralPath $parent).GetSecurityDescriptorBinaryForm())) } else { $null }
[IO.Directory]::CreateDirectory($root) | Out-Null
Assert-DiagnosticNoReparsePath $root
Assert-DiagnosticDirectoryPrivate $root # Read-only ACL verification. Fail; never broaden or rewrite permissions.
if ($testOnly) {
    $aclSnapshot = @{}
    foreach ($entry in @{ Parent = $parent; Child = $root }.GetEnumerator()) {
        $aclSnapshot[$entry.Key] = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Get-Acl -LiteralPath $entry.Value).GetSecurityDescriptorBinaryForm()))
    }
    if ($aclSnapshot.Parent -cne $parentAclBefore) { throw 'Parent ACL changed during child creation.' }
    Save-DiagnosticJson $aclSnapshot (Join-Path $root 'e2e-acl-snapshot.json')
}
$owner = @{ Version = 1; RunId = $RunId; JobName = "Local\adfl-auth-$RunId"; JobOwned = $false; TestOnly = $testOnly }
Save-DiagnosticJson $owner $ownerPath
Save-AuthenticatedManifest (New-AuthenticatedManifest) $accountPath
if ($testOnly) { [IO.File]::WriteAllText((Join-Path $root 'e2e-case.txt'), $E2ECase) }
$context = @{}; $exitCode = 2
try {
    $exitCode = Invoke-DiagnosticSupervisor @{
        Start = {
            param($current)
            $current.Job = [AdflProcessJob]::new($owner.JobName)
            $owner.JobOwned = $true; Save-DiagnosticJson $owner $ownerPath
            $coordinatorMode = if ($testOnly) { 'E2ECoordinator' } else { 'Coordinator' }
            $current.Process = Start-DiagnosticProcess (Join-Path $PSHOME 'pwsh.exe') @('-NoProfile', '-NonInteractive', '-File', $fixtureScriptPath, '-Mode', $coordinatorMode, '-RunId', $RunId, '-E2ECase', $E2ECase)
            $current.Capture = [AdflBoundedCapture]::new($current.Process)
        }
        Assign = { param($current) $current.Job.Assign($current.Process); $current.Timer = [Diagnostics.Stopwatch]::StartNew() }
        Release = { param($current) [AdflPrivateFrame]::Write($current.Process.StandardInput.BaseStream, $RunId); $current.Process.StandardInput.Close() }
        WaitSetup = {
            param($current, $milliseconds)
            while (!(Test-Path (Join-Path $root 'ready.json'))) {
                if ($current.Process.HasExited -or $current.Timer.ElapsedMilliseconds -ge $milliseconds) { throw 'Setup failed or timed out.' }
                Start-Sleep -Milliseconds 100
            }
            $ready = Get-Content -Raw (Join-Path $root 'ready.json') | ConvertFrom-Json
            if ($ready.RunId -cne $RunId -or $ready.Ready -ne $true) { throw 'Invalid setup readiness.' }
        }
        WaitComplete = { param($current, $milliseconds) if (!$current.Process.WaitForExit($milliseconds)) { throw 'Diagnostic timed out.' } }
        Read = { param($current) $null = $current.Capture.Result(); $current.Process.ExitCode }
        StopAndVerify = {
            param($current)
            if ($current.Job) { $current.Job.StopAndVerify() }
            if ($current.Process -and !$current.Process.HasExited) {
                $current.Process.Kill($true)
                if (!$current.Process.WaitForExit(10000)) { throw 'Unassigned worker remains.' }
            }
        }
        Cleanup = { param($current) Remove-Fixture }
        Dispose = { param($current) if ($current.Process) { $current.Process.Dispose() }; if ($current.Job) { $current.Job.Dispose() } }
    } $context
} catch {
    $stage = if (Test-Path $stagePath) { (Get-Content -Raw $stagePath) } else { 'not-started' }
    if ($stage -notmatch '^(accounts|logons|provider-key-create|certificate-(generate|export|import|verify)|managed-chain|pfx-write|setup-ready|net8|net10|complete|not-started)$') { $stage = 'withheld' }
    Write-Host "Diagnostic failed at stage=$stage; raw output withheld."
    $exitCode = 2
} finally {
    if (!$context.ShutdownConfirmed) { Write-Host 'Process shutdown unconfirmed; object cleanup blocked.' }
    elseif (!$context.CleanupConfirmed) { Write-Host 'Object cleanup incomplete; independent cleanup required.' }
    $history = Join-Path $root 'stages.txt'
    if ((Test-Path $history) -and (Get-Item $history).Length -le 4096) {
        foreach ($line in Get-Content $history) {
            if ($line -match '^(accounts|logons|provider-key-create|certificate-(generate|export|import|verify)|managed-chain|pfx-write|setup-ready|net8|net10|complete)$') { Write-Host "STAGE $line" }
            else { Write-Host 'STAGE unexpected text withheld' }
        }
    }
    try {
        $failurePath = Join-Path $root 'coordinator-failure.json'
        if ((Test-Path $failurePath) -and (Get-Item $failurePath).Length -le 4096) {
            $failure = Get-Content -Raw $failurePath | ConvertFrom-Json -AsHashtable
            if (($failure.NativeErrorCode -is [int] -or $failure.NativeErrorCode -is [long]) -and
                $failure.NativeErrorCode -ge [int]::MinValue -and $failure.NativeErrorCode -le [int]::MaxValue) {
                Write-Host "Coordinator failed: native-error=$($failure.NativeErrorCode); raw output withheld."
            }
        }
    } catch { Write-Host 'Coordinator failure detail unavailable.' }
}
exit $exitCode
