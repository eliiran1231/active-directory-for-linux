$ErrorActionPreference = 'Stop'
$key = [System.Security.Cryptography.RSA]::Create(2048)
$first = $null; $second = $null
$originalInput = [Console]::In
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=synthetic matcher test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $first = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
    $second = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
    $script:syntheticEvents = @()
    $record = 0
    foreach ($bytes in @($first.RawData, $second.RawData, [byte[]]@(1,2,3))) {
        $record++
        $script:syntheticEvents += [pscustomobject]@{
            RecordId = [long]$record; TimeCreated = [DateTime]::UtcNow
            Properties = @([pscustomobject]@{ Value = $bytes })
        }
    }
    # Shadow only the reader command in this test process. No event log access.
    function Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction) $script:syntheticEvents }
    $json = @{ Certificate = [Convert]::ToBase64String($first.RawData); Since = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
    [Console]::SetIn([System.IO.StringReader]::new($json))
    $lines = @(& "$PSScriptRoot/Match-SchannelCertificate.ps1" 6>&1 | ForEach-Object { $_.ToString() })
    if ($lines.Count -ne 3 -or @($lines | Where-Object { $_ -match 'exact-target-match=True$' }).Count -ne 1 -or
        @($lines | Where-Object { $_ -match 'exact-target-match=False$' }).Count -ne 2 -or
        @($lines | Where-Object { $_ -match 'unavailable or unsupported' }).Count -ne 1) {
        throw 'Matcher self-test failed; output withheld.'
    }
    if (@($lines | Where-Object { $_ -notmatch '^Schannel attribution: event=36882; utc=[0-9T:.Z+-]+; context=(whole-DER payload|certificate payload unavailable or unsupported); exact-target-match=(True|False)$' }).Count) {
        throw 'Unexpected matcher output; output withheld.'
    }
    Write-Host 'Matcher self-test passed: exact certificate, different certificate and unsupported payload; metadata-only output.'
} finally {
    [Console]::SetIn($originalInput)
    Remove-Item Function:Get-WinEvent -ErrorAction SilentlyContinue
    foreach ($resource in @($first, $second, $key)) { if ($null -ne $resource) { $resource.Dispose() } }
}
