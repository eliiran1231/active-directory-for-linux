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
        foreach ($mutation in @('instrumentation', 'cleanup', 'extra', 'missing', 'verdict', 'dependency', 'counts', 'outcome', 'query', 'findone-old-counts')) {
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
                'findone-old-counts' { $bad.Candidate['a/findone'].SourceBinds = 3; $bad.Candidate['a/findone'].SourceSearches = 6 }
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

foreach ($framework in @('net8.0', 'net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    $process = Start-DiagnosticProcess 'dotnet' @($binary, '--context-query-report-self-test')
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Query report self-test failed.' }
        $wrapper = $capture.Result() | ConvertFrom-Json -AsHashtable
        if (($wrapper.Keys | Sort-Object) -join ',' -cne 'Report,TestOnly' -or $wrapper.TestOnly -isnot [bool] -or !$wrapper.TestOnly) { throw 'Synthetic discriminator missing.' }
        $result = ConvertTo-ContextQueryResult ($wrapper.Report | ConvertTo-Json -Compress)
        if (!$result.FixedEligible -or !$result.FixedStable -or $result.Eligible) { throw 'Synthetic query comparison mismatch.' }
        foreach ($mutation in @('extra','stage','kind','code','verdict')) {
            $bad = $wrapper.Report | ConvertTo-Json | ConvertFrom-Json -AsHashtable
            switch ($mutation) {
                'extra' { $bad.TokenId = 123 }
                'stage' { $bad.FixedFirstStage = 'unapproved raw detail' }
                'kind' { $bad.FixedFirstKind = 'win32' }
                'code' { $bad.FixedFirstCode = 5 }
                'verdict' { $bad.FixedEligible = $false }
            }
            $rejected = $false
            try { $null = ConvertTo-ContextQueryResult ($bad | ConvertTo-Json -Compress) } catch { $rejected = $true }
            if (!$rejected) { throw 'Unsafe query report accepted.' }
        }
        Write-Host "PASS $framework fixed-stage query report and pre-security gate contract; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure query worker remains.' } }
        $process.Dispose()
    }
}

foreach ($framework in @('net8.0', 'net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    $process = Start-DiagnosticProcess 'dotnet' @($binary, '--continuation-report-self-test')
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Pure continuation report worker failed.' }
        $wrapper = $capture.Result() | ConvertFrom-Json -AsHashtable
        if (($wrapper.Keys | Sort-Object) -join ',' -cne 'Report,TestOnly' -or $wrapper.TestOnly -isnot [bool] -or !$wrapper.TestOnly) { throw 'Synthetic discriminator missing.' }
        $json = $wrapper.Report | ConvertTo-Json -Depth 10 -Compress
        $report = ConvertTo-ContinuationCandidateResult $json
        if ($report.Continuations.Count -ne 4 -or $report.Supported -ne 'passed' -or $report.Adverse -ne 'failed' -or $report.AllPassed) { throw 'Continuation contract failed.' }
        foreach ($mutation in @('extra','missing','unknown-case','cleanup','pool','identity','attempts','sends','searches','binds','schema','references','reuse','partial-reuse','partial-code','code-type','array-type','label','order','phase','kind','failure','verdict','dependency','comparison','case-cleanup','negative','overflow','boolean-counter')) {
            $bad = $json | ConvertFrom-Json -AsHashtable
            $row = $bad.Continuations['onelevel/success'].Scoped
            switch ($mutation) {
                'extra' { $row.Secret = 'synthetic' }
                'missing' { $bad.Continuations.Remove('subtree/partial') }
                'unknown-case' { $bad.Continuations['unknown'] = $bad.Continuations['subtree/partial'] }
                'cleanup' { $row.Cleanup = $false }
                'pool' { $row.PoolDelta = 1 }
                'identity' { $row.IdentityValid = $false }
                'attempts' { $row.Attempts = 1 }
                'sends' { $row.Sends = 3 }
                'searches' { $row.TargetSearches = 3 }
                'binds' { $row.SourceBinds = 3 }
                'schema' { $row.SchemaReads = 3 }
                'references' { $row.References = 1 }
                'reuse' { $row.Reused = 0 }
                'partial-reuse' { $bad.Continuations['subtree/partial'].Scoped.Reused = 1 }
                'partial-code' { $bad.Continuations['subtree/partial'].Scoped.Results = @(0,0) }
                'code-type' { $row.Results = @('0',0) }
                'array-type' { $row.Results = 0 }
                'label' { $row.Returned = @('raw private detail','local') }
                'order' { $row.Returned = @('target','local') }
                'phase' { $row.Phase = 'raw private detail' }
                'kind' { $row.FailureKind = 'raw private detail' }
                'failure' { $row.FailureCode = 81 }
                'verdict' { $bad.AllPassed = $true }
                'dependency' { $row.Status = 'skipped' }
                'comparison' { $bad.Continuations['onelevel/success'].Status = 'failed' }
                'case-cleanup' { $bad.Continuations['onelevel/success'].Cleanup = $false }
                'negative' { $row.TargetBinds = -1 }
                'overflow' { $row.TargetBinds = 2147483648 }
                'boolean-counter' { $row.TargetBinds = $true }
            }
            $rejected = $false
            try { $null = ConvertTo-ContinuationCandidateResult ($bad | ConvertTo-Json -Depth 10 -Compress) } catch { $rejected = $true }
            if (!$rejected) { throw "Malformed continuation $mutation accepted." }
        }
        # Valid failures remain reportable, including a separate teardown failure and original LDAP error.
        $bad = $json | ConvertFrom-Json -AsHashtable
        $case = $bad.Continuations['subtree/success']; $row = $case.Scoped
        $row.Status = 'failed'; $row.Phase = 'read'; $row.FailureKind = 'ldap'; $row.FailureCode = 81
        $row.Cleanup = $false; $row.PoolDelta = 1; $case.Cleanup = $false; $case.Status = 'failed'; $bad.Supported = 'failed'
        $result = ConvertTo-ContinuationCandidateResult ($bad | ConvertTo-Json -Depth 10 -Compress)
        if ($result.Continuations['subtree/success'].Scoped.FailureCode -ne 81 -or $result.Continuations['subtree/success'].Cleanup) { throw 'Failure evidence lost.' }
        # A failed original direct gate produces four completely empty skipped comparisons.
        $bad = $json | ConvertFrom-Json -AsHashtable
        $bad.Native['original-direct'].Status = 'failed'
        $bad.Native['original-referral'].Status = 'skipped'; $bad.Native['original-retained-primary'].Status = 'skipped'
        foreach ($case in $bad.Continuations.Values) {
            $case.Status = 'skipped'
            foreach ($mode in @('Ordinary','Scoped')) {
                $row = $case[$mode]; $row.Status = 'skipped'; $row.Phase = 'not-started'; $row.IdentityValid = $false
                $row.Results = @(); $row.Returned = @()
                foreach ($field in @('Attempts','Sends','SourceBinds','SourceSearches','BindingReads','SchemaReads','Continuations','References','TargetBinds','TargetSearches','Reused')) { $row[$field] = 0 }
            }
        }
        $bad.Supported = 'failed'
        $null = ConvertTo-ContinuationCandidateResult ($bad | ConvertTo-Json -Depth 10 -Compress)
        $bad.Continuations['onelevel/success'].Scoped.Sends = 1
        $rejected = $false
        try { $null = ConvertTo-ContinuationCandidateResult ($bad | ConvertTo-Json -Depth 10 -Compress) } catch { $rejected = $true }
        if (!$rejected) { throw 'Skipped operation accepted.' }
        Write-Host "PASS $framework continuation inventory, 30 rejection cases, skipped dependencies and preserved operation/cleanup failures; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure continuation worker remains.' } }
        $process.Dispose()
    }
}

# Parse and execute only the inert Preflight path in both new invocation modes.
$fixture = Join-Path $PSScriptRoot 'Authenticated-Fixture.ps1'
& $fixture -Mode Preflight -ContinuationCandidate
foreach ($invoke in @({ & $fixture -Mode Preflight -ContextCandidate -ContinuationCandidate }, { & $fixture -Mode E2ESupervisor -ContinuationCandidate })) {
    $rejected = $false
    try { & $invoke | Out-Null } catch { $rejected = $true }
    if (!$rejected) { throw 'Conflicting or E2E continuation mode accepted.' }
}
Write-Host 'PASS inert continuation preflight and mode conflicts; no setup.'

# A parser rejection travels through the real runtime orchestration finally path.
$events = [Collections.Generic.List[string]]::new()
$ops = @{
    Start = { param($context) }; Assign = { param($context) }
    CopyA = { param($context) 'fake-a' }; CopyB = { param($context) 'fake-b' }
    Release = { param($context, $a, $b) }; Wait = { param($context, $timeout) }
    Read = { param($context) ConvertTo-ContinuationCandidateResult '{"invalid":true}' }
    StopAndVerify = { param($context) $events.Add('stop') }
    Dispose = { param($context) $events.Add('dispose') }
}
$rejected = $false
try { $null = Invoke-DiagnosticRuntime $ops } catch { $rejected = $true }
if (!$rejected -or ($events -join ',') -cne 'stop,dispose') { throw 'Parser failure escaped runtime teardown.' }
Write-Host 'PASS actual parser rejection invokes stop verification then disposal with fake transport.'

foreach ($framework in @('net8.0','net10.0')) {
    $binary = Join-Path $PSScriptRoot "worker/bin/Release/$framework/AuthenticatedWorker.dll"
    $process = Start-DiagnosticProcess 'dotnet' @($binary, '--external-scope-report-self-test')
    try {
        $capture = [AdflBoundedCapture]::new($process)
        if (!$process.WaitForExit(30000) -or $process.ExitCode -ne 0) { throw 'Pure external scope report worker failed.' }
        $wrapper = $capture.Result() | ConvertFrom-Json -AsHashtable
        if (($wrapper.Keys | Sort-Object) -join ',' -cne 'Report,TestOnly' -or $wrapper.TestOnly -isnot [bool] -or !$wrapper.TestOnly) { throw 'Synthetic discriminator missing.' }
        $json = $wrapper.Report | ConvertTo-Json -Depth 10 -Compress
        $report = ConvertTo-ExternalScopeResult $json
        if ($report.ExternalScopes.Count -ne 2 -or $report.Supported -ne 'passed' -or $report.Adverse -ne 'failed' -or $report.AllPassed) { throw 'External scope verdict failed.' }
        $rejected = $false
        try { $null = ConvertTo-ContinuationCandidateResult $json } catch { $rejected = $true }
        if (!$rejected) { throw 'External report reinterpreted as historical continuation report.' }
        foreach ($mutation in @('missing','unknown','extra','no-target','duplicate','local-entry','continuation','result-code','reuse','cleanup','pool','identity','send','verdict','skipped')) {
            $bad = $json | ConvertFrom-Json -AsHashtable
            $row = $bad.ExternalScopes['onelevel/external'].Scoped
            switch ($mutation) {
                'missing' { $bad.ExternalScopes.Remove('subtree/external') }
                'unknown' { $bad.ExternalScopes['onelevel/success'] = $bad.ExternalScopes['onelevel/external'] }
                'extra' { $row.Secret = 'synthetic' }
                'no-target' { $row.TargetSearches = 0; $row.TargetBinds = 0 }
                'duplicate' { $row.TargetSearches = 3 }
                'local-entry' { $row.Returned = @('local','local') }
                'continuation' { $row.Continuations = 2; $row.References = 2 }
                'result-code' { $row.Results = @(4,4) }
                'reuse' { $row.Reused = 0 }
                'cleanup' { $row.Cleanup = $false }
                'pool' { $row.PoolDelta = 1 }
                'identity' { $row.IdentityValid = $false }
                'send' { $row.Sends = 3 }
                'verdict' { $bad.AllPassed = $true }
                'skipped' { $row.Status = 'skipped' }
            }
            $rejected = $false
            try { $null = ConvertTo-ExternalScopeResult ($bad | ConvertTo-Json -Depth 10 -Compress) } catch { $rejected = $true }
            if (!$rejected) { throw "Invalid external scope $mutation accepted." }
        }
        $bad = $json | ConvertFrom-Json -AsHashtable
        $case = $bad.ExternalScopes['onelevel/external']; $row = $case.Scoped
        $row.Status = 'failed'; $row.Phase = 'read'; $row.FailureKind = 'ldap'; $row.FailureCode = 81
        $row.Cleanup = $false; $row.PoolDelta = 1; $case.Status = 'failed'; $case.Cleanup = $false; $bad.Supported = 'failed'
        $result = ConvertTo-ExternalScopeResult ($bad | ConvertTo-Json -Depth 10 -Compress)
        if ($result.ExternalScopes['onelevel/external'].Scoped.FailureCode -ne 81 -or $result.ExternalScopes['onelevel/external'].Cleanup) { throw 'External failure evidence lost.' }
        Write-Host "PASS $framework separate two-case external scope inventory, strict evidence and failure contract; no native operations."
    } finally {
        if (!$process.HasExited) { $process.Kill($true); if (!$process.WaitForExit(10000)) { throw 'Pure external worker remains.' } }
        $process.Dispose()
    }
}
& $fixture -Mode Preflight -ExternalScopeCandidate
foreach ($invoke in @({ & $fixture -Mode Preflight -ContextCandidate -ExternalScopeCandidate },
    { & $fixture -Mode Preflight -ContinuationCandidate -ExternalScopeCandidate }, { & $fixture -Mode E2ESupervisor -ExternalScopeCandidate })) {
    $rejected = $false
    try { & $invoke | Out-Null } catch { $rejected = $true }
    if (!$rejected) { throw 'Conflicting external scope mode accepted.' }
}
Write-Host 'PASS external scope inert preflight and all mode conflicts.'
