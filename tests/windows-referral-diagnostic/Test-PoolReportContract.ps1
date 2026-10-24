# Pure executable serialization contract; no accounts, tokens, keys, stores or network.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Process.cs')
foreach ($framework in @('net8.0', 'net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    $process = Start-DiagnosticProcess 'dotnet' @($binary, '--pool-report-self-test')
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Pure report worker failed.' }
        $wrapper = $capture.Result() | ConvertFrom-Json -AsHashtable
        if (($wrapper.Keys | Sort-Object) -join ',' -cne 'Report,TestOnly' -or $wrapper.TestOnly -isnot [bool] -or !$wrapper.TestOnly) { throw 'Synthetic discriminator missing.' }
        $report = ConvertTo-DiagnosticCombinedResult ($wrapper.Report | ConvertTo-Json -Depth 8 -Compress)
        if ($report.Supported -ne 'passed' -or $report.Adverse -ne 'failed' -or $report.AllPassed -or $report.Pool.Count -ne 34) { throw 'Combined verdict contract failed.' }
        Write-Host "PASS $framework synthetic native/pool report serialization, schema and separate adverse verdict; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure report worker remains.' } }
        $process.Dispose()
    }
}
