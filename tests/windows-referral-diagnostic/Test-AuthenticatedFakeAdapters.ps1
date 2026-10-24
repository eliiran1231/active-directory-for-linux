# Pure adapter regression: dummy files only; never load real Windows adapters.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Fixture-Core.ps1')
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
. (Join-Path $PSScriptRoot 'Authenticated-E2E-Adapters.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('adfl-fake-unit-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $root) { throw 'Test directory preexists.' }
[IO.Directory]::CreateDirectory($root) | Out-Null
$RunId = [Guid]::NewGuid().ToString('N'); $E2ECase = 'Success'
$accountPath = Join-Path $root 'accounts.json'; $certificatePath = Join-Path $root 'certificate.json'
try {
    $state = New-AuthenticatedManifest
    Save-AuthenticatedManifest $state $accountPath
    $ops = New-E2EAccountOperations
    Initialize-AuthenticatedAccounts $state { Save-AuthenticatedManifest $state $accountPath } $ops
    if ((Read-E2EAccounts).Count -ne 2 -or $state.Accounts[1].State -ne 'owned') { throw 'Fake accounts did not round trip.' }
    $transfer = [pscustomobject]@{}
    $transfer | Add-Member ScriptMethod CopyTo { param($process) return [long]101 }
    $transfer | Add-Member ScriptMethod Dispose { }
    $a = New-E2EToken 1 $transfer
    if ($a.CopyTo($null).ToString([Globalization.CultureInfo]::InvariantCulture) -cne '101') { throw 'Fake handoff scalar mismatch.' }
    $a.Dispose()
    if (!(Test-Path -LiteralPath (Join-Path $root 'e2e-token-1-disposed.txt'))) { throw 'Fake dispose missing.' }
    $E2ECase = 'PartialHandoff'; $b = New-E2EToken 2 $transfer; $failed = $false
    try { $null = $b.CopyTo($null) } catch { $failed = $true }
    if (!$failed -or [IO.File]::ReadAllText((Join-Path $root 'e2e-fault.txt')) -cne 'PartialHandoff') { throw 'Fake handoff fault not reached.' }
    $b.Dispose(); $E2ECase = 'Success'
    $ops.StopWorker = { }; $ops.Certificate = { Remove-E2ECertificate }; $ops.Pfx = { }
    if ((Remove-AuthenticatedObjects $state $ops).Count -ne 0 -or (Read-E2EAccounts).Count -ne 0) { throw 'Fake cleanup failed.' }
    Write-Host 'Fake adapter file round trips, scalar handoff, disposal and cleanup passed; no real identity or trust operations.'
} finally {
    foreach ($file in Get-ChildItem -LiteralPath $root -Force) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected test child.' }
        Remove-Item -LiteralPath $file.FullName
    }
    [IO.Directory]::Delete($root, $false)
}
