$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Compare-CertificateDer.ps1"
$key = [System.Security.Cryptography.RSA]::Create(2048)
$first = $null; $second = $null
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=synthetic matcher test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $first = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
    $second = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
    $same = Compare-CertificateDer -Bytes $first.RawData -Expected $first.RawData
    $different = Compare-CertificateDer -Bytes $second.RawData -Expected $first.RawData
    $invalid = Compare-CertificateDer -Bytes ([byte[]]@(1,2,3)) -Expected $first.RawData
    $wrapped = Compare-CertificateDer -Bytes ([byte[]](@(0) + $first.RawData)) -Expected $first.RawData
    if (!$same.Parsed -or !$same.ExactMatch) { throw 'Exact DER self-test failed.' }
    if (!$different.Parsed -or $different.ExactMatch) { throw 'Different DER self-test failed.' }
    if ($invalid.Parsed -or $invalid.ExactMatch) { throw 'Invalid DER self-test failed.' }
    if ($wrapped.Parsed -or $wrapped.ExactMatch) { throw 'Wrapped DER self-test failed.' }
    Write-Host 'Matcher self-test passed: exact, different, invalid and wrapped DER; no event-log access.'
} finally {
    foreach ($resource in @($first, $second, $key)) { if ($null -ne $resource) { $resource.Dispose() } }
}
