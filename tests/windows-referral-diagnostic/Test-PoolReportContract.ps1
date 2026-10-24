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
        if ($report.Supported -ne 'passed' -or $report.Adverse -ne 'failed' -or $report.AllPassed -or $report.Pool.Count -ne 37) { throw 'Combined verdict contract failed.' }
        Write-Host "PASS $framework synthetic native/pool report serialization, schema and separate adverse verdict; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure report worker remains.' } }
        $process.Dispose()
    }
}

foreach ($framework in @('net8.0', 'net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    $process = Start-DiagnosticProcess 'dotnet' @($binary, '--context-report-self-test')
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Pure candidate report worker failed.' }
        $wrapper = $capture.Result() | ConvertFrom-Json -AsHashtable
        if (($wrapper.Keys | Sort-Object) -join ',' -cne 'Report,TestOnly' -or $wrapper.TestOnly -isnot [bool] -or !$wrapper.TestOnly) { throw 'Synthetic discriminator missing.' }
        $report = ConvertTo-ContextCandidateResult ($wrapper.Report | ConvertTo-Json -Depth 8 -Compress)
        if ($report.Candidate.Count -ne 31 -or $report.Supported -ne 'passed' -or $report.Adverse -ne 'failed' -or $report.AllPassed) { throw 'Candidate contract failed.' }
        foreach ($mutation in @('instrumentation', 'cleanup', 'extra', 'missing', 'verdict', 'dependency', 'counts', 'outcome', 'query')) {
            $bad = $wrapper.Report | ConvertTo-Json -Depth 8 | ConvertFrom-Json -AsHashtable
            switch ($mutation) {
                'instrumentation' { $bad.Candidate['a/stable'].InstrumentationFailed = $true }
                'cleanup' { $bad.Candidate['a/stable'].Cleanup = $false }
                'extra' { $bad.Candidate['a/stable'].Secret = 'synthetic' }
                'missing' { $bad.Candidate.Remove('a/stable') }
                'verdict' { $bad.AllPassed = $true }
                'dependency' { $bad.Candidate['a/stable'].Status = 'skipped' }
                'counts' { $bad.Candidate['a/stable'].TargetSearches = 4 }
                'outcome' { $bad.Candidate['anonymous/first'].WarmKind = 'directory' }
                'query' { $bad.Candidate['a/stable'].QueryStage = 'unapproved raw detail' }
            }
            $rejected = $false
            try { $null = ConvertTo-ContextCandidateResult ($bad | ConvertTo-Json -Depth 8 -Compress) } catch { $rejected = $true }
            if (!$rejected) { throw "Candidate malformed $mutation accepted." }
        }
        Write-Host "PASS $framework candidate report schema, dependency and redaction rejection checks; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure worker remains.' } }
        $process.Dispose()
    }
}
