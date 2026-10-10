param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('net8.0', 'net10.0')]
    [string] $Framework,
    [ValidateSet('boundary', 'size', 'mixed', 'retained-export', 'composition', 'raw-contract', 'alarm')]
    [string] $Mode = 'boundary'
)
$ErrorActionPreference = 'Stop'
# The preceding ordinary oracle step builds this executable. Each native batch is
# isolated and bounded; preserve partial JSONL/log output if a batch fails or hangs.
$directory = "artifacts/$Mode/$Framework"
$total = if ($Mode -eq 'alarm') { 96 } elseif ($Mode -eq 'raw-contract') { 80 } elseif ($Mode -eq 'composition') { 48 } elseif ($Mode -eq 'retained-export') { 296 } elseif ($Mode -eq 'mixed') { 64 } elseif ($Mode -eq 'size') { 316 } else { 220 }
$option = if ($Mode -eq 'alarm') { '--sddl-alarm-jsonl' } elseif ($Mode -eq 'raw-contract') { '--sddl-raw-contract-jsonl' } elseif ($Mode -eq 'composition') { '--sddl-composition-jsonl' } elseif ($Mode -eq 'retained-export') { '--sddl-retained-export-jsonl' } elseif ($Mode -eq 'mixed') { '--sddl-mixed-jsonl' } elseif ($Mode -eq 'size') { '--sddl-size-followup-jsonl' } else { '--sddl-boundary-jsonl' }
if ($Mode -in @('mixed', 'retained-export', 'composition', 'raw-contract', 'alarm')) { $env:DOTNET_GCHeapHardLimit = '0x10000000'; $env:DOTNET_PROCESSOR_COUNT = '2' }
New-Item -ItemType Directory -Force $directory | Out-Null
$assembly = "docs/research/acl-windows-oracle/bin/Release/$Framework/AclWindowsOracle.dll"
for ($start = 0; $start -lt $total; $start += 16) {
    $stem = "$directory/boundary-$('{0:D3}' -f $start)"
    $process = Start-Process dotnet -ArgumentList @($assembly, $option, "$stem.jsonl", $start, 16) -PassThru -NoNewWindow -RedirectStandardOutput "$stem.stdout.log" -RedirectStandardError "$stem.stderr.log"
    if (!$process.WaitForExit(60000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "Boundary batch $start timed out; partial evidence retained."
    }
    $process.WaitForExit()
    Get-Content "$stem.stderr.log"
    if ($process.ExitCode -ne 0) { throw "Boundary batch $start exited $($process.ExitCode)." }
    $rows = @(Get-Content "$stem.jsonl" | ForEach-Object { ConvertFrom-Json $_ })
    $expected = [Math]::Min(16, $total - $start)
    if ($rows.Count -ne $expected + 1 -or $rows[0].Start -ne $start -or $rows[0].Count -ne $expected -or $rows[0].TotalCases -ne $total) {
        throw "Incomplete boundary batch $start."
    }
    for ($i = 0; $i -lt $expected; $i++) {
        if ($rows[$i + 1].Kind -ne 'Observation' -or $rows[$i + 1].Case -ne $start + $i) {
            throw "Unexpected boundary case sequence in batch $start."
        }
    }
    # The full UTF-16 inputs/hex outcomes remain in artifacts. Emit the exact JSONL
    # bytes compressed as well: expanded size cases exceed connector log transport
    # limits. Hash the uncompressed bytes so recovery verifies the original file.
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path "$stem.jsonl"))
    $memory = [System.IO.MemoryStream]::new()
    $gzip = [System.IO.Compression.GZipStream]::new($memory, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $gzip.Write($bytes, 0, $bytes.Length)
    $gzip.Dispose()
    $record = @{ Start = $start; Mode = $Mode; Framework = $Framework; Sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)); GzipBase64 = [Convert]::ToBase64String($memory.ToArray()) }
    $memory.Dispose()
    Write-Output ('SDDL_BOUNDARY_GZIP=' + ($record | ConvertTo-Json -Compress))
}
Write-Output "Verified $total complete native $Mode observations on $Framework; no portable parity claim."
