param([switch]$SkipWindowsMetadata)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
. (Join-Path $PSScriptRoot 'Certificate-Material.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Process.cs')
if (!$SkipWindowsMetadata) {
    if (!$IsWindows) { throw 'Windows metadata check requires Windows.' }
    # Metadata only: none of these account/group cmdlets is invoked.
    $required = @{
        'New-LocalUser' = @('Name', 'Password', 'Description')
        'Get-LocalUser' = @()
        'Remove-LocalUser' = @('SID')
        'Get-LocalGroupMember' = @('SID')
        'Add-LocalGroupMember' = @('SID', 'Member')
    }
    foreach ($name in $required.Keys) {
        $command = Get-Command -Name $name -CommandType Cmdlet -ErrorAction Stop
        $matches = @($command.ParameterSets | Where-Object {
            $names = @($_.Parameters.Name)
            @($required[$name] | Where-Object { $_ -notin $names }).Count -eq 0
        })
        if ($matches.Count -eq 0) { throw 'Required account cmdlet parameter set unavailable.' }
    }
    Write-Host 'LocalAccounts command/parameter metadata passed; no account cmdlets invoked.'
}
$stages = [Collections.Generic.List[string]]::new()
function Stage([string]$Name) { $stages.Add($Name) }
$material = New-DiagnosticCertificateMaterial ([Guid]::NewGuid().ToString('N')) { param($name) Stage $name }
try {
    if (($stages -join ',') -cne 'certificate-generate,certificate-export' -or $material.Public.HasPrivateKey -or !$material.Certificate.HasPrivateKey) { throw 'Material preparation invariant failed.' }
    foreach ($framework in @('net8.0', 'net10.0')) {
        $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
        $process = Start-DiagnosticProcess 'dotnet' @($binary, '--certificate-material-self-test')
        try {
            $capture = [AdflBoundedCapture]::new($process)
            # Generated test key material stays in memory and a bounded private pipe, never argv/files/artifacts/logs.
            [AdflPrivateFrame]::Write($process.StandardInput.BaseStream, [Convert]::ToBase64String($material.Pfx))
            $process.StandardInput.Close()
            if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Ephemeral material round trip failed.' }
            $result = $capture.Result() | ConvertFrom-Json -AsHashtable
            if (($result.Keys | Sort-Object) -join ',' -cne 'HasPrivateKey,SignatureVerified,Thumbprint' -or
                $result.HasPrivateKey -isnot [bool] -or !$result.HasPrivateKey -or
                $result.SignatureVerified -isnot [bool] -or !$result.SignatureVerified -or
                $result.Thumbprint -isnot [string] -or $result.Thumbprint -cne $material.Public.Thumbprint) { throw 'Ephemeral material verification failed.' }
            Write-Host "PASS $framework ephemeral material round trip; no store access, chain build or key files."
        } finally {
            if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Material worker remains.' } }
            $process.Dispose()
        }
    }
} finally { Remove-DiagnosticCertificateMaterial $material }
if (@($material.Pfx | Where-Object { $_ -ne 0 }).Count -ne 0) { throw 'Material buffer not cleared.' }
Write-Host 'Shared certificate preparation and explicit buffer cleanup passed; no trust changes.'
