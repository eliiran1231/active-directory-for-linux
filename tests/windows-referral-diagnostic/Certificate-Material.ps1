# No stores, file writes or chain building. Default preparation is ephemeral.
# The real authenticated fixture may supply its separately owned named CNG key;
# that path exports public DER only and never exports a PFX/private key.
function Remove-DiagnosticCertificateMaterial($Material) {
    if ($null -eq $Material) { return }
    if ($null -ne $Material.Pfx) { [Array]::Clear($Material.Pfx, 0, $Material.Pfx.Length) }
    foreach ($name in @('Public', 'Certificate', 'Key')) { if ($null -ne $Material[$name]) { $Material[$name].Dispose() } }
}
function New-DiagnosticCertificateMaterial([string]$RunId, [scriptblock]$Stage = { param($name) }, $ExistingKey = $null) {
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') { throw 'Invalid certificate identifier.' }
    $material = @{ Key = $null; Certificate = $null; Public = $null; Pfx = $null }
    try {
        & $Stage 'certificate-generate'
        $material.Key = if ($null -ne $ExistingKey) { [Security.Cryptography.RSACng]::new($ExistingKey) } else { [Security.Cryptography.RSA]::Create(2048) }
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=ADFL ephemeral $RunId", $material.Key,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $names = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $names.AddIpAddress([Net.IPAddress]::Loopback); $names.AddDnsName('localhost')
        $request.CertificateExtensions.Add($names.Build())
        $oids = [Security.Cryptography.OidCollection]::new(); $oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
        $material.Certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
        & $Stage 'certificate-export'
        $material.Public = [Security.Cryptography.X509Certificates.X509Certificate2]::new($material.Certificate.Export('Cert'))
        if ($material.Public.HasPrivateKey) { throw 'Public certificate required.' }
        if ($null -eq $ExistingKey) { $material.Pfx = $material.Certificate.Export('Pfx') }
        return $material
    } catch { Remove-DiagnosticCertificateMaterial $material; throw }
}
