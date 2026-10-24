$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Owned-Key.ps1')
. (Join-Path $PSScriptRoot 'Authenticated-Fixture-Core.ps1')
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
function AssertKey($value) { if (!$value) { throw 'Owned-key regression failed.' } }
function RejectKey([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    AssertKey $rejected
}
# Exercise the actual factory closure and atomic writer in both enclosing invocation
# scopes, but never invoke any native adapter callback. Dummy non-secret file only.
$dummyPath = Join-Path ([IO.Path]::GetTempPath()) ('adfl-key-save-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    $realOps = New-DiagnosticKeyOperations $dummyPath
    & $realOps.Save @{ Dummy = 'non-secret'; State = 'creating' }
    AssertKey ((Get-Content -Raw -LiteralPath $dummyPath | ConvertFrom-Json).State -ceq 'creating')
    & $realOps.Save @{ Dummy = 'non-secret'; State = 'owned' }
    AssertKey ((Get-Content -Raw -LiteralPath $dummyPath | ConvertFrom-Json).State -ceq 'owned')
    AssertKey (!(Test-Path -LiteralPath "$dummyPath.new"))
} finally {
    foreach ($path in @($dummyPath, "$dummyPath.new")) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path } }
}
$runId = 'a' * 32
foreach ($case in @('success', 'preexisting', 'create-failure', 'save-failure', 'creating', 'sid', 'provider', 'name', 'run-id', 'hash', 'delete-failure', 'query-failure', 'remains', 'absent')) {
    $record = @{ Version = 1; RunId = $runId; Name = "adfl-auth-$runId"; Provider = $DiagnosticKeyProvider; Sid = 'synthetic-owner'; State = 'creating'; PublicHash = $null }
    $state = @{ Exists = ($case -eq 'preexisting'); Calls = [Collections.Generic.List[string]]::new(); Saved = $null; Saves = 0; Queries = 0 }
    $key = [pscustomobject]@{ State = $state }
    $key | Add-Member ScriptMethod Dispose { $this.State.Calls.Add('dispose') }
    $ops = @{
        CurrentSid = { 'synthetic-owner' }
        Exists = { param($r) $state.Queries++; if ($case -eq 'query-failure' -and $state.Queries -gt 1) { throw 'synthetic query failure' }; $state.Exists }
        Save = { param($r) $state.Saves++; if ($case -eq 'save-failure' -and $state.Saves -eq 2) { throw 'synthetic durable write failure' }; $state.Saved = $r | ConvertTo-Json | ConvertFrom-Json -AsHashtable; $state.Calls.Add('save') }
        Create = { param($r) $state.Calls.Add('create'); if ($case -eq 'create-failure') { throw 'synthetic create failure' }; $state.Exists = $true; $key }
        Open = { param($r) $state.Calls.Add('open'); $key }
        Hash = { param($k) if ($case -eq 'hash' -and $state.Calls.Contains('open')) { 'B' * 64 } else { 'A' * 64 } }
        Delete = { param($k) $state.Calls.Add('delete'); if ($case -eq 'delete-failure') { throw 'synthetic delete failure' }; if ($case -ne 'remains') { $state.Exists = $false } }
    }
    if ($case -in @('preexisting', 'create-failure', 'save-failure')) {
        RejectKey { New-DiagnosticOwnedKey $record $ops }
        if ($case -eq 'preexisting') { AssertKey (!$state.Calls.Contains('create') -and !$state.Calls.Contains('save')) }
        else { AssertKey ($state.Saved.State -eq 'creating'); RejectKey { Remove-DiagnosticOwnedKey $state.Saved $runId $ops } }
        AssertKey (!$state.Calls.Contains('delete'))
        continue
    }
    $created = New-DiagnosticOwnedKey $record $ops
    AssertKey ($state.Saved.State -eq 'owned' -and $state.Calls[0] -eq 'save' -and $state.Calls[1] -eq 'create')
    if ($case -eq 'creating') { $record.State = 'creating' }
    if ($case -eq 'sid') { $record.Sid = 'different-owner' }
    if ($case -eq 'provider') { $record.Provider = 'different-provider' }
    if ($case -eq 'name') { $record.Name = 'different-name' }
    if ($case -eq 'run-id') { $record.RunId = 'b' * 32 }
    if ($case -eq 'absent') { $state.Exists = $false }
    if ($case -in @('success', 'absent')) {
        Remove-DiagnosticOwnedKey $record $runId $ops
        AssertKey (!$state.Exists)
        AssertKey ($state.Queries -ge 3)
    } else {
        RejectKey { Remove-DiagnosticOwnedKey $record $runId $ops }
        if ($case -in @('creating', 'sid', 'provider', 'name', 'run-id', 'hash', 'query-failure')) { AssertKey (!$state.Calls.Contains('delete')) }
    }
    $created.Dispose()
}
# Even independent key cleanup failure cannot hide certificate/PFX cleanup attempts.
$attempted = [Collections.Generic.List[string]]::new()
$cleanup = @{
    StopWorker = { $attempted.Add('stop') }
    Certificate = { $attempted.Add('cert'); throw 'synthetic certificate failure' }
    ProviderKey = { $attempted.Add('key'); throw 'synthetic provider failure' }
    Pfx = { $attempted.Add('pfx') }
}
$failures = Remove-AuthenticatedObjects $null $cleanup
AssertKey (($attempted -join ',') -ceq 'stop,cert,key,pfx')
AssertKey ($failures -contains 'ProviderKey' -and $failures -contains 'Certificate')
Write-Host 'Owned-key fake ownership, partial failure and independent cleanup regressions passed; no native key operations.'
