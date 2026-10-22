$ErrorActionPreference = 'Stop'
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
                $bytes = $property.Value
                if ($bytes -isnot [byte[]] -or $bytes.Length -gt 65536) { continue }
                # Accept only an entire DER certificate binary property. No
                # offset scanning, XML dumping or guessed payload envelopes.
                $certificate = $null
                try {
                    if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($bytes) -ne
                        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) { continue }
                    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
                    $raw = $certificate.RawData
                    if ($raw.Length -ne $bytes.Length) { continue }
                    $wholeDer = $true
                    for ($i = 0; $i -lt $raw.Length; $i++) {
                        if ($raw[$i] -ne $bytes[$i]) { $wholeDer = $false; break }
                    }
                    if (!$wholeDer) { continue }
                    $parsed = $true
                    $equal = $raw.Length -eq $expected.Length
                    for ($i = 0; $equal -and $i -lt $raw.Length; $i++) {
                        if ($raw[$i] -ne $expected[$i]) { $equal = $false }
                    }
                    if ($equal) { $exact = $true }
                } catch {
                    # Unsupported binary fields are not interpreted or printed.
                } finally { if ($null -ne $certificate) { $certificate.Dispose() } }
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
