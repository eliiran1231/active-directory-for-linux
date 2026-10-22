function Compare-CertificateDer {
    param($Bytes, [byte[]]$Expected)
    $result = [pscustomobject]@{ Parsed = $false; ExactMatch = $false }
    if ($Bytes -isnot [byte[]] -or $Bytes.Length -gt 65536) { return $result }
    $certificate = $null
    try {
        # Accept only an entire DER certificate. No offset scanning or guessed
        # envelopes. This is a public in-memory object, not a store or key import.
        if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes) -ne
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) { return $result }
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Bytes)
        $raw = $certificate.RawData
        if ($raw.Length -ne $Bytes.Length) { return $result }
        for ($i = 0; $i -lt $raw.Length; $i++) {
            if ($raw[$i] -ne $Bytes[$i]) { return $result }
        }
        $result.Parsed = $true
        $equal = $raw.Length -eq $Expected.Length
        for ($i = 0; $equal -and $i -lt $raw.Length; $i++) {
            if ($raw[$i] -ne $Expected[$i]) { $equal = $false }
        }
        $result.ExactMatch = $equal
        return $result
    } catch { return $result }
    finally { if ($null -ne $certificate) { $certificate.Dispose() } }
}
