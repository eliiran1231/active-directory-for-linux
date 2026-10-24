# No operation runs when dot-sourced. Real adapter is used only by the approved fixture.
$DiagnosticKeyProvider = 'Microsoft Software Key Storage Provider'
function Assert-DiagnosticKeyRecord($Record, [string]$RunId, [string]$Sid) {
    if ($Record.Version -ne 1 -or $Record.RunId -cne $RunId -or $RunId -cnotmatch '^[0-9a-f]{32}$' -or
        $Record.Name -cne "adfl-auth-$RunId" -or $Record.Provider -cne $DiagnosticKeyProvider -or
        $Record.Sid -cne $Sid -or $Record.State -notin @('creating', 'owned') -or
        ($Record.State -eq 'owned' -and $Record.PublicHash -cnotmatch '^[0-9A-F]{64}$')) { throw 'Invalid key ownership.' }
}
function New-DiagnosticOwnedKey($Record, $Operations) {
    Assert-DiagnosticKeyRecord $Record $Record.RunId (& $Operations.CurrentSid)
    if ($Record.State -ne 'creating' -or (& $Operations.Exists $Record)) { throw 'Key already exists or invalid creation state.' }
    & $Operations.Save $Record # Durable intent BEFORE creation, without overwrite permission.
    $key = & $Operations.Create $Record
    try {
        $Record.PublicHash = & $Operations.Hash $key $Record
        $Record.State = 'owned'
        & $Operations.Save $Record # A failed save leaves creating on disk: fail closed during cleanup.
        return $key
    } catch { $key.Dispose(); throw }
}
function Remove-DiagnosticOwnedKey($Record, [string]$RunId, $Operations) {
    Assert-DiagnosticKeyRecord $Record $RunId (& $Operations.CurrentSid)
    # An interrupted creation is unresolved, even when an absence query returns false.
    if ($Record.State -ne 'owned') { throw 'Unresolved key ownership.' }
    if (& $Operations.Exists $Record) {
        $key = & $Operations.Open $Record
        try {
            if ((& $Operations.Hash $key $Record) -cne $Record.PublicHash) { throw 'Key public identity mismatch.' }
            & $Operations.Delete $key
        } finally { $key.Dispose() }
    }
    if (& $Operations.Exists $Record) { throw 'Provider key remains.' }
}
function New-DiagnosticKeyOperations([string]$ManifestPath) {
    $saveJson = ${function:Save-DiagnosticJson}
    if ($null -eq $saveJson) { throw 'Durable JSON writer required.' }
    return @{
        CurrentSid = { $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); try { $identity.User.Value } finally { $identity.Dispose() } }
        Exists = { param($r) [Security.Cryptography.CngKey]::Exists($r.Name, [Security.Cryptography.CngProvider]::new($r.Provider), [Security.Cryptography.CngKeyOpenOptions]::None) }
        Save = { param($r) & $saveJson $r $ManifestPath }.GetNewClosure()
        Create = { param($r)
            $p = [Security.Cryptography.CngKeyCreationParameters]::new()
            $p.Provider = [Security.Cryptography.CngProvider]::new($r.Provider)
            $p.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::None # user key, never overwrite
            $p.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
            $p.KeyUsage = [Security.Cryptography.CngKeyUsages]::AllUsages
            $p.Parameters.Add([Security.Cryptography.CngProperty]::new('Length', [BitConverter]::GetBytes([int]2048), [Security.Cryptography.CngPropertyOptions]::None))
            [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $r.Name, $p)
        }
        Open = { param($r) [Security.Cryptography.CngKey]::Open($r.Name, [Security.Cryptography.CngProvider]::new($r.Provider), [Security.Cryptography.CngKeyOpenOptions]::None) }
        Hash = { param($key, $r)
            if ($key.Provider.Provider -cne 'Microsoft Software Key Storage Provider' -or $key.IsMachineKey -or
                $key.IsEphemeral -or $key.KeyName -cne $r.Name -or $key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $key.Algorithm.Algorithm -cne 'RSA' -or $key.KeySize -ne 2048) { throw 'Unexpected provider key properties.' }
            $rsa = [Security.Cryptography.RSACng]::new($key)
            try { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo())) }
            finally { $rsa.Dispose() }
        }
        Delete = { param($key) $key.Delete() }
    }
}
