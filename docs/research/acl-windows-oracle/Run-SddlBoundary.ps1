param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('net8.0', 'net10.0')]
    [string] $Framework
)
$ErrorActionPreference = 'Stop'
# The preceding ordinary oracle step builds this executable. Each native batch is
# isolated and bounded; preserve partial JSONL/log output if a batch fails or hangs.
$directory = "artifacts/boundary/$Framework"
New-Item -ItemType Directory -Force $directory | Out-Null
$assembly = "docs/research/acl-windows-oracle/bin/Release/$Framework/AclWindowsOracle.dll"
for ($start = 0; $start -lt 220; $start += 16) {
    $stem = "$directory/boundary-$('{0:D3}' -f $start)"
    $process = Start-Process dotnet -ArgumentList @($assembly, '--sddl-boundary-jsonl', "$stem.jsonl", $start, 16) -PassThru -NoNewWindow -RedirectStandardOutput "$stem.stdout.log" -RedirectStandardError "$stem.stderr.log"
    if (!$process.WaitForExit(60000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "Boundary batch $start timed out; partial evidence retained."
    }
    $process.WaitForExit()
    Get-Content "$stem.stdout.log"
    Get-Content "$stem.stderr.log"
    if ($process.ExitCode -ne 0) { throw "Boundary batch $start exited $($process.ExitCode)." }
    $rows = @(Get-Content "$stem.jsonl" | ForEach-Object { ConvertFrom-Json $_ })
    $expected = [Math]::Min(16, 220 - $start)
    if ($rows.Count -ne $expected + 1 -or $rows[0].Start -ne $start -or $rows[0].Count -ne $expected -or $rows[0].TotalCases -ne 220) {
        throw "Incomplete boundary batch $start."
    }
    for ($i = 0; $i -lt $expected; $i++) {
        if ($rows[$i + 1].Kind -ne 'Observation' -or $rows[$i + 1].Case -ne $start + $i) {
            throw "Unexpected boundary case sequence in batch $start."
        }
    }
}
Write-Output "Verified 220 complete native boundary observations on $Framework; no portable parity claim."
