$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Referral-Stages.ps1')

# Inject outcomes, never invoke the fixture helper, Windows APIs or certificate IO.
$cases = @(
    @{ Fail = @(); Calls = 'original-direct,anonymous-direct,original-baseline,original-reuse,impersonation'; Impersonation = 'passed' },
    @{ Fail = @('anonymous-direct'); Calls = 'original-direct,anonymous-direct,original-baseline,original-reuse'; Impersonation = 'skipped' },
    @{ Fail = @('original-direct'); Calls = 'original-direct,anonymous-direct'; Impersonation = 'skipped' },
    @{ Fail = @('original-direct', 'anonymous-direct'); Calls = 'original-direct,anonymous-direct'; Impersonation = 'skipped' },
    @{ Fail = @('original-baseline'); Calls = 'original-direct,anonymous-direct,original-baseline'; Impersonation = 'skipped' },
    @{ Fail = @('original-reuse'); Calls = 'original-direct,anonymous-direct,original-baseline,original-reuse'; Impersonation = 'skipped' },
    @{ Fail = @('impersonation'); Calls = 'original-direct,anonymous-direct,original-baseline,original-reuse,impersonation'; Impersonation = 'failed' }
)
foreach ($case in $cases) {
    $calls = [System.Collections.Generic.List[string]]::new()
    $results = Invoke-ReferralStages {
        param($name)
        $calls.Add($name)
        return $name -notin $case.Fail
    }
    if (($calls -join ',') -ne $case.Calls) { throw "Wrong dependency order for $($case.Fail -join ',')" }
    if ($results['impersonation'] -ne $case.Impersonation) { throw 'Wrong impersonation outcome.' }
    foreach ($failure in $case.Fail) {
        if ($results[$failure] -ne 'failed') { throw 'Failure was hidden.' }
    }
    if ('anonymous-direct' -in $case.Fail -and 'original-direct' -notin $case.Fail) {
        if ($results['original-baseline'] -ne 'passed' -or $results['original-reuse'] -ne 'passed') {
            throw 'Anonymous failure suppressed independent original-identity evidence.'
        }
    }
}
$rejected = $false
try { Invoke-ReferralStages { 'passed' } | Out-Null }
catch { $rejected = $true }
if (!$rejected) { throw 'Non-Boolean stage outcome was accepted.' }
Write-Host 'Stage dependency regressions passed: seven outcome cases and invalid-runner rejection.'

# Parse all orchestration code without executing the trust helper.
foreach ($name in @('Machine-Trust-Fixture.ps1', 'Referral-Stages.ps1', 'Test-ReferralStages.ps1')) {
    $tokens = $null; $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
}
