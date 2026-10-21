param([switch]$Cleanup)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only a disposable GitHub-hosted Windows runner is permitted.'
}
$directory = Join-Path $env:RUNNER_TEMP 'adfl-referral-trust-once'
$manifest = Join-Path $directory 'thumbprint.txt'
$pfx = Join-Path $directory 'loopback.pfx'
function Remove-Fixture {
    if (Test-Path $manifest) {
        $thumbprint = (Get-Content -Raw $manifest).Trim()
        if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw 'Invalid exact thumbprint manifest.' }
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        try {
            $store.Open('ReadWrite')
            $matches = $store.Certificates.Find('FindByThumbprint', $thumbprint, $false)
            foreach ($certificate in $matches) { $store.Remove($certificate) }
            if ($store.Certificates.Find('FindByThumbprint', $thumbprint, $false).Count -ne 0) {
                throw "Removal verification failed for $thumbprint"
            }
            Write-Host "Verified absent from CurrentUser Root: $thumbprint"
        } finally { $store.Dispose() }
    }
    if (Test-Path $pfx) { Remove-Item -LiteralPath $pfx -Force }
    Remove-Item Env:ADFL_REFERRAL_TEST_PFX -ErrorAction SilentlyContinue
}
if ($Cleanup) { Remove-Fixture; exit 0 }
if (Test-Path $directory) { throw 'Diagnostic already initialized; refusing another trust operation.' }
New-Item -ItemType Directory -Path $directory | Out-Null
$key = [System.Security.Cryptography.RSA]::Create(2048)
$generated = $null
$public = $null
$store = $null
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=ADFL disposable loopback TEST', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $names = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $names.AddIpAddress([System.Net.IPAddress]::Loopback)
    $names.AddDnsName('localhost')
    $request.CertificateExtensions.Add($names.Build())
    $oids = [System.Security.Cryptography.OidCollection]::new()
    $oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
    $generated = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
    $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($generated.Export('Cert'))
    if ($public.HasPrivateKey) { throw 'Trust-store certificate must be public only.' }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
    $store.Open('ReadWrite')
    if ($store.Certificates.Find('FindByThumbprint', $public.Thumbprint, $false).Count -ne 0) { throw 'Certificate already exists.' }
    # Record exact identity before any store mutation, for the always() cleanup.
    Set-Content -LiteralPath $manifest -Value $public.Thumbprint
    [System.IO.File]::WriteAllBytes($pfx, $generated.Export('Pfx'))
    $store.Add($public)
    Write-Host "Temporarily trusted public TEST certificate: $($public.Thumbprint); expires $($public.NotAfter.ToUniversalTime().ToString('O'))"
    $store.Dispose(); $store = $null
    $env:ADFL_REFERRAL_TEST_PFX = $pfx
    $failed = $false
    foreach ($framework in @('net8.0', 'net10.0')) {
        & dotnet test tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj --configuration Release --framework $framework --filter 'FullyQualifiedName~AdForLinux.FunctionalTests.WindowsBasicReferralTests.' --logger 'console;verbosity=detailed' --logger "trx;LogFileName=trusted-$framework.trx" --results-directory artifacts
        if ($LASTEXITCODE -ne 0) { $failed = $true }
    }
    if ($failed) { throw 'Native diagnostic assertions failed; inspect both runtime results.' }
} finally {
    if ($null -ne $store) { $store.Dispose() }
    try { Remove-Fixture } finally {
        if ($null -ne $public) { $public.Dispose() }
        if ($null -ne $generated) { $generated.Dispose() }
        $key.Dispose()
    }
}
