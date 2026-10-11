param([Parameter(Mandatory = $true)][ValidateSet('net8.0', 'net10.0')][string] $Framework,
    [ValidateSet('layers', 'ace-size')][string] $Mode = 'layers')
$ErrorActionPreference = 'Stop'
$directory = "artifacts/$Mode/$Framework"
New-Item -ItemType Directory -Force $directory | Out-Null
$assembly = "docs/research/acl-windows-oracle/bin/Release/$Framework/AclWindowsOracle.dll"
$countArgument = if ($Mode -eq 'ace-size') { '--sddl-ace-size-count' } else { '--sddl-layer-count' }
$jsonArgument = if ($Mode -eq 'ace-size') { '--sddl-ace-size-jsonl' } else { '--sddl-layer-jsonl' }
$total = [int] (& dotnet $assembly $countArgument)
if ($LASTEXITCODE -ne 0 -or $total -lt 1 -or $total -gt 1000) { throw 'Invalid layer manifest.' }
$env:DOTNET_GCHeapHardLimit = '0x10000000'
$env:DOTNET_PROCESSOR_COUNT = '2'
$failures = 0
for ($index = 0; $index -lt $total; $index++) {
    $stem = "$directory/layer-$('{0:D3}' -f $index)"
    $process = Start-Process dotnet -ArgumentList @($assembly, $jsonArgument, "$stem.jsonl", $index) -PassThru -NoNewWindow -RedirectStandardOutput "$stem.stdout.log" -RedirectStandardError "$stem.stderr.log"
    $finished = $process.WaitForExit(15000)
    if (!$finished) { $process.Kill($true) }
    $process.WaitForExit()
    $complete = $false
    if (Test-Path "$stem.jsonl") {
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path "$stem.jsonl"))
        $memory = [System.IO.MemoryStream]::new()
        $gzip = [System.IO.Compression.GZipStream]::new($memory, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        $gzip.Write($bytes, 0, $bytes.Length); $gzip.Dispose()
        $record = @{ Mode = $Mode; Case = $index; Framework = $Framework; Total = $total; Sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)); GzipBase64 = [Convert]::ToBase64String($memory.ToArray()) }
        $memory.Dispose()
        Write-Output ('SDDL_LAYER_GZIP=' + ($record | ConvertTo-Json -Compress))
        try {
            $rows = @(Get-Content "$stem.jsonl" | ForEach-Object { ConvertFrom-Json $_ })
            $complete = $rows.Count -eq 3 -and $rows[0].Kind -eq 'Attempt' -and $rows[1].Kind -eq 'Native' -and $rows[2].Kind -eq 'Managed' -and @($rows | Where-Object { $_.Case -ne $index }).Count -eq 0
            if ($rows[1].InspectionError -or $rows[1].LocalFreeSucceeded -eq $false) { $complete = $false }
        } catch { $complete = $false }
    }
    Get-Content "$stem.stderr.log"
    $status = @{ Case = $index; Complete = $complete; ExitCode = $process.ExitCode; TimedOut = !$finished }
    $status | ConvertTo-Json -Compress | Set-Content "$stem.status.json"
    Write-Output ('SDDL_LAYER_STATUS=' + ($status | ConvertTo-Json -Compress))
    if (!$complete -or !$finished -or $process.ExitCode -ne 0) { $failures++ }
}
if ($failures -ne 0) { throw "$failures isolated layer cases failed; partial evidence and statuses retained." }
Write-Output "Verified $total isolated native layer cases on $Framework."
