param([switch]$CleanupOnly, [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$BatchId)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_RUN_ID -notmatch '^\d+$') { throw 'Hosted Windows required.' }
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Process.cs')
$fixture = Join-Path $PSScriptRoot 'Authenticated-Fixture.ps1'
$parent = [IO.Path]::GetDirectoryName((Get-DiagnosticRoot $env:LOCALAPPDATA $BatchId))
Assert-DiagnosticNoReparsePath $parent
Assert-DiagnosticDirectoryPrivate $parent
$batchPath = Join-Path $parent "adfl-e2e-batch-$BatchId.json"
function Invoke-E2EFixture([string]$Mode, [string]$Id, [string]$Case) {
    if ($Mode -notin @('E2ESupervisor', 'E2ECleanup')) { throw 'Only fake adapters permitted.' }
    $process = Start-DiagnosticProcess (Join-Path $PSHOME 'pwsh.exe') @('-NoProfile', '-NonInteractive', '-File', $fixture, '-Mode', $Mode, '-RunId', $Id, '-E2ECase', $Case)
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(120000)) { throw 'Outer E2E watchdog elapsed.' }
        $null = $capture.Result() # Fixed diagnostics only, not synthetic native result publication.
        return $process.ExitCode
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'E2E fixture process remains.' } }
        $process.Dispose()
    }
}
function Read-Batch {
    $batch = Get-Content -Raw -LiteralPath $batchPath | ConvertFrom-Json -AsHashtable
    if ($batch.Version -ne 1 -or $batch.BatchId -cne $BatchId -or $batch.WorkflowRun -cne $env:GITHUB_RUN_ID -or
        $batch.TestOnly -isnot [bool] -or !$batch.TestOnly) { throw 'Invalid E2E batch ownership.' }
    foreach ($entry in $batch.Cases) {
        if ($entry.Id -cnotmatch '^[0-9a-f]{32}$' -or $entry.Case -notin @('Success', 'SetupEarlyExit', 'SecondCreateFailure', 'SetupTimeout', 'RuntimeTimeout', 'PartialHandoff', 'MalformedOutput', 'OutputOverflow', 'EarlyExit', 'TruncatedFrame', 'CleanupFailures')) { throw 'Invalid E2E case.' }
    }
    return $batch
}
function Verify-AndRemove-E2ERoot($Entry) {
    $root = Get-DiagnosticRoot $env:LOCALAPPDATA $Entry.Id
    if (!(Test-Path -LiteralPath $root)) { return }
    Assert-DiagnosticNoReparsePath $root
    Assert-DiagnosticDirectoryPrivate $root
    $owner = Get-Content -Raw -LiteralPath (Join-Path $root 'owner.json') | ConvertFrom-Json -AsHashtable
    if ($owner.RunId -cne $Entry.Id -or $owner.TestOnly -isnot [bool] -or !$owner.TestOnly -or $owner.JobName -cne "Local\adfl-auth-$($Entry.Id)") { throw 'Not an owned fake fixture.' }
    [AdflProcessJob]::StopRecorded($owner.JobName)
    $code = Invoke-E2EFixture 'E2ECleanup' $Entry.Id $Entry.Case
    $expected = if ($Entry.Case -eq 'SecondCreateFailure') { 2 } else { 0 }
    if ($code -ne $expected) { throw 'Independent fake cleanup outcome unexpected.' }
    $accounts = Join-Path $root 'e2e-accounts.json'
    if ((Test-Path -LiteralPath $accounts) -and (Get-Content -Raw -LiteralPath $accounts | ConvertFrom-Json -AsHashtable).Count -ne 0) { throw 'Fake accounts remain.' }
    foreach ($leaf in @('loopback.pfx', 'e2e-certificate.txt')) {
        if (Test-Path -LiteralPath (Join-Path $root $leaf)) { throw 'Dummy sensitive-shaped file remains.' }
    }
    $snapshot = Get-Content -Raw -LiteralPath (Join-Path $root 'e2e-acl-snapshot.json') | ConvertFrom-Json -AsHashtable
    foreach ($pair in @{ Parent = $parent; Child = $root }.GetEnumerator()) {
        $now = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Get-Acl -LiteralPath $pair.Value).GetSecurityDescriptorBinaryForm()))
        if ($snapshot[$pair.Key] -cne $now) { throw 'ACL changed during dummy setup.' }
    }
    $allowed = @('owner.json', 'accounts.json', 'certificate.json', 'stage.txt', 'stages.txt', 'ready.json', 'coordinator-failure.json',
        'e2e-case.txt', 'e2e-accounts.json', 'e2e-acl-snapshot.json', 'e2e-copy-1.txt', 'e2e-copy-2.txt', 'e2e-fault.txt',
        'e2e-worker-ready-net8.0.txt', 'e2e-worker-ready-net10.0.txt', 'e2e-descendant-started.txt.new',
        'e2e-handles-closed-net8.0.txt', 'e2e-handles-closed-net10.0.txt',
        'e2e-token-1-disposed.txt', 'e2e-token-2-disposed.txt', 'e2e-descendant-started.txt',
        'e2e-account-cleanup-fault.txt', 'e2e-certificate-cleanup-fault.txt',
        'net8.0-e2e-results.json', 'net10.0-e2e-results.json', 'net8.0-failure.json', 'net10.0-failure.json')
    $files = @(Get-ChildItem -LiteralPath $root -Force)
    foreach ($file in $files) {
        if ($file.PSIsContainer -or $file.Name -notin $allowed -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected object; no recursive removal.' }
        Assert-DiagnosticDirectoryPrivate $file.FullName # Actual inherited file ACLs, including dummy records.
    }
    foreach ($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
    [IO.Directory]::Delete($root, $false)
    if (Test-Path -LiteralPath $root) { throw 'Owned empty fixture child remains.' }
}
if ($CleanupOnly) {
    if (!(Test-Path -LiteralPath $batchPath)) { Write-Host 'E2E batch already absent.'; exit 0 }
    $batch = Read-Batch; $failed = $false
    foreach ($entry in $batch.Cases) {
        try { Verify-AndRemove-E2ERoot $entry }
        catch { $failed = $true; Write-Host "E2E cleanup incomplete case=$($entry.Case); details withheld." }
    }
    if ($failed) { exit 2 }
    Remove-Item -LiteralPath $batchPath
    if (Test-Path -LiteralPath $batchPath) { throw 'Batch manifest remains.' }
    Write-Host 'E2E independent cleanup verified all owned dummy files and children absent.'
    exit 0
}
if (Test-Path -LiteralPath $batchPath) { throw 'Batch preexists; do not reuse.' }
$batch = @{ Version = 1; BatchId = $BatchId; WorkflowRun = $env:GITHUB_RUN_ID; TestOnly = $true; Cases = @() }
Save-DiagnosticJson $batch $batchPath
foreach ($case in @('Success', 'SetupEarlyExit', 'SecondCreateFailure', 'SetupTimeout', 'RuntimeTimeout', 'PartialHandoff', 'MalformedOutput', 'OutputOverflow', 'EarlyExit', 'TruncatedFrame', 'CleanupFailures')) {
    $id = [Guid]::NewGuid().ToString('N'); $root = Get-DiagnosticRoot $env:LOCALAPPDATA $id
    if (Test-Path -LiteralPath $root) { throw 'Candidate preexists; no ownership assumed.' }
    $entry = @{ Id = $id; Case = $case }; $batch.Cases += $entry
    Save-DiagnosticJson $batch $batchPath
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $code = Invoke-E2EFixture 'e2esupervisor' $id $case # Case-insensitive mode boundary must remain fake.
    $expected = if ($case -eq 'Success') { 0 } else { 2 }
    if ($code -ne $expected) { throw "E2E case=$case exit=$code expected=$expected." }
    $stages = @(Get-Content -LiteralPath (Join-Path $root 'stages.txt'))
    if ($case -ne 'Success') {
        $fault = Join-Path $root 'e2e-fault.txt'
        if (!(Test-Path -LiteralPath $fault) -or [IO.File]::ReadAllText($fault) -cne $case) { throw "Intended E2E fault not reached: $case." }
        $expectedStage = switch ($case) {
            'SetupEarlyExit' { 'accounts' }
            'SecondCreateFailure' { 'accounts' }
            'SetupTimeout' { 'certificate-import' }
            'CleanupFailures' { 'complete' }
            default { 'net8' }
        }
        if ($stages[-1] -cne $expectedStage) { throw "Unexpected terminal E2E stage: $case." }
        if ($case -eq 'SecondCreateFailure') {
            $ownership = Get-Content -Raw -LiteralPath (Join-Path $root 'accounts.json') | ConvertFrom-Json
            if ($ownership.Accounts[0].State -ne 'owned' -or !$ownership.Accounts[0].Sid -or $ownership.Accounts[1].State -ne 'creating') { throw 'Partial creation ordering not exercised.' }
        }
        if ($case -eq 'SetupTimeout' -and $elapsed.ElapsedMilliseconds -lt 60000) { throw 'Setup failed before watchdog, not an exercised timeout.' }
        if ($case -eq 'PartialHandoff') {
            if ([IO.File]::ReadAllText((Join-Path $root 'e2e-copy-1.txt')) -cne '1' -or
                (Test-Path -LiteralPath (Join-Path $root 'e2e-copy-2.txt'))) { throw 'Partial handoff ordering not exercised.' }
        }
        if ($case -in @('RuntimeTimeout', 'MalformedOutput', 'OutputOverflow', 'EarlyExit', 'TruncatedFrame')) {
            if (!(Test-Path -LiteralPath (Join-Path $root 'e2e-worker-ready-net8.0.txt'))) { throw 'Actual worker startup not reached.' }
        }
        if ($case -eq 'CleanupFailures') {
            foreach ($leaf in @('e2e-account-cleanup-fault.txt', 'e2e-certificate-cleanup-fault.txt', 'net8.0-e2e-results.json', 'net10.0-e2e-results.json')) {
                if (!(Test-Path -LiteralPath (Join-Path $root $leaf))) { throw 'Cleanup failure combination not exercised.' }
            }
            if ((Get-Content -Raw -LiteralPath (Join-Path $root 'e2e-accounts.json') | ConvertFrom-Json -AsHashtable).Count -ne 1 -or
                (Test-Path -LiteralPath (Join-Path $root 'loopback.pfx'))) { throw 'Cleanup did not continue after injected failure.' }
        }
    }
    if ($case -eq 'Success') {
        if ($stages -notcontains 'complete') { throw 'Successful path did not complete.' }
        foreach ($framework in @('net8.0', 'net10.0')) {
            $null = ConvertTo-DiagnosticResult (Get-Content -Raw -LiteralPath (Join-Path $root "$framework-e2e-results.json"))
            if (!(Test-Path -LiteralPath (Join-Path $root "e2e-handles-closed-$framework.txt"))) { throw 'Transferred event handles not verified/closed.' }
        }
        foreach ($index in @(1, 2)) {
            if ([IO.File]::ReadAllText((Join-Path $root "e2e-copy-$index.txt")) -cne '2' -or
                !(Test-Path -LiteralPath (Join-Path $root "e2e-token-$index-disposed.txt"))) { throw 'Fake handoff/disposal sequence missing.' }
        }
        # Cleanup cannot cross the explicit mode discriminator even for owned paths.
        $ownerPath = Join-Path $root 'owner.json'
        $owner = Get-Content -Raw -LiteralPath $ownerPath | ConvertFrom-Json -AsHashtable
        $owner.TestOnly = $false; Save-DiagnosticJson $owner $ownerPath
        try {
            if ((Invoke-E2EFixture 'E2ECleanup' $id $case) -ne 2) { throw 'Cross-mode cleanup accepted.' }
        } finally { $owner.TestOnly = $true; Save-DiagnosticJson $owner $ownerPath }
    } elseif ($case -ne 'CleanupFailures' -and $stages -contains 'net10') { throw 'Failure allowed dependent next runtime.' }
    if ($case -eq 'RuntimeTimeout' -and !(Test-Path -LiteralPath (Join-Path $root 'e2e-descendant-started.txt'))) { throw 'Timeout did not exercise a descendant.' }
    Verify-AndRemove-E2ERoot $entry
    Write-Host "E2E PASS case=$case real-filesystem+IPC+containment+cleanup; identities/trust synthetic only."
}
