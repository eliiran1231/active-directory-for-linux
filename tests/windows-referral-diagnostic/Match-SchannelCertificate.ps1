$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Compare-CertificateDer.ps1"
try {
    if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
        throw 'Hosted Windows required.'
    }
    # Public DER arrives only on a redirected anonymous stdin pipe, never argv,
    # environment, a file, an artifact or console output.
    $inputData = [Console]::In.ReadLine() | ConvertFrom-Json
    $expected = [Convert]::FromBase64String($inputData.Certificate)
    $since = [DateTime]::Parse($inputData.Since)
    $seen = [System.Collections.Generic.HashSet[long]]::new()
    $matched = $false
    for ($attempt = 0; $attempt -lt 5 -and !$matched; $attempt++) {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'; ProviderName = 'Schannel'; Id = 36882; StartTime = $since
            } -MaxEvents 50 -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $events = @()
        }
        foreach ($event in $events) {
            if (!$seen.Add($event.RecordId)) { continue }
            $exact = $false
            $parsed = $false
            foreach ($property in $event.Properties) {
                $comparison = Compare-CertificateDer -Bytes $property.Value -Expected $expected
                if ($comparison.Parsed) { $parsed = $true }
                if ($comparison.ExactMatch) { $exact = $true }
            }
            $context = if ($parsed) { 'whole-DER payload' } else { 'certificate payload unavailable or unsupported' }
            Write-Host "Schannel attribution: event=36882; utc=$($event.TimeCreated.ToUniversalTime().ToString('o')); context=$context; exact-target-match=$exact"
            if ($exact) { $matched = $true }
        }
        if (!$matched -and $attempt -lt 4) { Start-Sleep -Seconds 1 }
    }
    if ($seen.Count -eq 0) { Write-Host 'Schannel attribution: context=no matching event in bounded observation window; exact-target-match=False' }
} catch {
    # Never emit exception messages, raw event data, stdin or certificates.
    Write-Host 'Schannel attribution: context=read or parser unavailable; exact-target-match=False'
}
