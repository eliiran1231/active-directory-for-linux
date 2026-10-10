param([Parameter(Mandatory = $true)][ValidateSet('net8.0','net10.0')][string] $Framework)
$ErrorActionPreference = 'Stop'
$directory = "artifacts/assembly/$Framework"
New-Item -ItemType Directory -Force $directory | Out-Null
$assembly = "docs/research/acl-windows-oracle/bin/Release/$Framework/AclWindowsOracle.dll"
$env:DOTNET_GCHeapHardLimit = '0x10000000'
$env:DOTNET_PROCESSOR_COUNT = '2'
for ($index = 0; $index -lt 8; $index++) {
    $stem = "$directory/witness-$index"
    $process = Start-Process dotnet -ArgumentList @($assembly,'--sddl-assembly-jsonl',"$stem.jsonl",$index) -PassThru -NoNewWindow -RedirectStandardOutput "$stem.stdout.log" -RedirectStandardError "$stem.stderr.log"
    $finished = $process.WaitForExit(15000)
    if (!$finished) { $process.Kill($true) }
    $process.WaitForExit()
    Get-Content "$stem.stderr.log"
    if (!$finished -or $process.ExitCode -ne 0) { throw "Witness $index did not complete; partial evidence retained." }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path "$stem.jsonl"))
    $rows = @(Get-Content "$stem.jsonl" | ForEach-Object { ConvertFrom-Json $_ })
    if ($rows.Count -ne 4 -or ($rows.Kind -join ',') -ne 'Attempt,Native,Compile,Replay' -or @($rows | Where-Object { $_.Case -ne $index }).Count -ne 0) { throw 'Incomplete assembly probe.' }
    $memory = [System.IO.MemoryStream]::new()
    $gzip = [System.IO.Compression.GZipStream]::new($memory,[System.IO.Compression.CompressionLevel]::Optimal,$true)
    $gzip.Write($bytes,0,$bytes.Length); $gzip.Dispose()
    $record = @{ Case=$index; Framework=$Framework; Sha256=[Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)); GzipBase64=[Convert]::ToBase64String($memory.ToArray()) }
    Write-Output ('SDDL_ASSEMBLY_GZIP=' + ($record | ConvertTo-Json -Compress))
    $memory.Dispose()
}
Write-Output "Recorded eight isolated assembly witnesses on $Framework; localization evidence only."
