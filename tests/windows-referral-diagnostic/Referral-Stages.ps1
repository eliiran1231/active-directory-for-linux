# Pure orchestration. The injected runner must return a single Boolean indicating
# one fully executed native test result, never managed-chain diagnostic status.
function Invoke-ReferralStages([scriptblock]$Run) {
    $results = [ordered]@{}
    foreach ($name in @('original-direct', 'anonymous-direct', 'original-baseline', 'original-reuse', 'impersonation')) {
        $allowed = switch ($name) {
            'original-direct' { $true }
            'anonymous-direct' { $true }
            'original-baseline' { $results['original-direct'] -eq 'passed' }
            'original-reuse' { $results['original-baseline'] -eq 'passed' }
            'impersonation' {
                $results['original-direct'] -eq 'passed' -and
                $results['anonymous-direct'] -eq 'passed' -and
                $results['original-baseline'] -eq 'passed' -and
                $results['original-reuse'] -eq 'passed'
            }
        }
        if (!$allowed) { $results[$name] = 'skipped'; continue }
        $passed = & $Run $name
        if ($passed -isnot [bool]) { throw 'Stage runner must return exactly one Boolean.' }
        $results[$name] = if ($passed) { 'passed' } else { 'failed' }
    }
    return $results
}
