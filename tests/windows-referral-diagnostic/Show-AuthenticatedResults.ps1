# Read-only output step for a future explicitly approved job. Never launches a worker.
param([Parameter(Mandatory)][string]$RunId)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
$root = Get-DiagnosticRoot $env:LOCALAPPDATA $RunId
if (!(Test-Path -LiteralPath $root)) { Write-Host 'No native or pool results; fixture directory absent.'; return }
Assert-DiagnosticNoReparsePath $root
Assert-DiagnosticDirectoryPrivate $root
foreach ($framework in @('net8.0', 'net10.0')) {
    $path = Join-Path $root "$framework-results.json"
    if (!(Test-Path -LiteralPath $path)) { Write-Host "$framework has no completed native/pool result."; continue }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid result file withheld.' }
    $result = ConvertTo-DiagnosticCombinedResult (Get-Content -Raw -LiteralPath $path)
    Write-Host "$framework supported=$($result.Supported) anonymous-adverse=$($result.Adverse) all-passed=$($result.AllPassed)"
    $result | ConvertTo-Json -Depth 8 -Compress | Write-Host
}
