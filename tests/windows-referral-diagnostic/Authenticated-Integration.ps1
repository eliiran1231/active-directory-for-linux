# Definition-only helpers, also exercised with pure inputs by preflight.
function Get-DiagnosticNativeErrorCode($Value) {
    $exception = if ($Value -is [Exception]) { $Value } else { $Value.Exception }
    for ($index = 0; $index -lt 8 -and $exception; $index++) {
        if ($exception -is [ComponentModel.Win32Exception]) { return $exception.NativeErrorCode }
        $exception = $exception.InnerException
    }
    return 0 # Unavailable, not a claim of native success.
}
function Invoke-DiagnosticSupervisor($Operations, $Context) {
    try {
        & $Operations.Start $Context
        & $Operations.Assign $Context
        & $Operations.Release $Context
        & $Operations.WaitSetup $Context 60000
        & $Operations.WaitComplete $Context 420000
        return & $Operations.Read $Context
    } finally {
        try {
            & $Operations.StopAndVerify $Context
            $Context.ShutdownConfirmed = $true
            & $Operations.Cleanup $Context
            $Context.CleanupConfirmed = $true
        } finally { & $Operations.Dispose $Context }
    }
}
function Invoke-DiagnosticRuntime($Operations) {
    $context = @{}
    try {
        & $Operations.Start $context
        & $Operations.Assign $context
        $first = & $Operations.CopyA $context
        $second = & $Operations.CopyB $context
        & $Operations.Release $context $first $second
        & $Operations.Wait $context 180000
        return & $Operations.Read $context
    } finally {
        try { & $Operations.StopAndVerify $context }
        finally { & $Operations.Dispose $context }
    }
}
function Test-DiagnosticPrivateAccess([string]$Owner, [string]$Runner, [string[]]$AllowedSids) {
    $permitted = @($Runner, 'S-1-5-18', 'S-1-5-32-544')
    return ($AllowedSids.Count -gt 0 -and $Owner -in $permitted -and @($AllowedSids | Where-Object { $_ -notin $permitted }).Count -eq 0)
}
function Assert-DiagnosticDirectoryPrivate([string]$Path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $acl = Get-Acl -LiteralPath $Path
        $allow = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object AccessControlType -EQ 'Allow' | ForEach-Object { $_.IdentityReference.Value })
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (!(Test-DiagnosticPrivateAccess $owner $identity.User.Value $allow)) { throw 'Inherited directory ACL is not private; do not change it.' }
    } finally { $identity.Dispose() }
}
function Save-DiagnosticJson($Value, [string]$Path) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress))
    $temporary = "$Path.new"
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($temporary, $Path, $true)
}
function Start-DiagnosticProcess([string]$File, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new($File)
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    foreach ($prefix in @('DOTNET', 'COMPlus')) {
        $info.Environment["${prefix}_DbgEnableMiniDump"] = '0'
        $info.Environment["${prefix}_EnableDiagnostics"] = '0'
    }
    $info.Environment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'
    return [Diagnostics.Process]::Start($info)
}
function ConvertTo-DiagnosticResult([string]$Json) {
    if ($Json.Length -gt 65536) { throw 'Output limit exceeded.' }
    $value = $Json | ConvertFrom-Json -AsHashtable
    $expected = @('original-direct', 'original-referral', 'original-retained-primary', 'a-direct', 'a-referral', 'a-retained-primary',
        'b-direct', 'b-referral', 'b-retained-primary', 'a-to-b', 'b-to-a', 'anonymous-direct')
    if ((($value.Keys | Sort-Object) -join ',') -cne (($expected | Sort-Object) -join ',')) { throw 'Unexpected result fields.' }
    foreach ($name in $expected) {
        $row = $value[$name]
        if (($row.Keys | Sort-Object) -join ',' -cne 'Anonymous,Binds,Closed,Connections,FailureCode,FailureKind,Phase,PrimaryBinds,PrimarySearches,Sasl,Searches,Status,Tls') { throw 'Unexpected observation fields.' }
        if ($row.Status -notin @('passed', 'failed', 'skipped')) { throw 'Invalid stage status.' }
        if ($row.Phase -notin @('initialization', 'create', 'bind', 'search', 'complete') -or
            $row.FailureKind -notin @('none', 'ldap', 'directory', 'native', 'fixture') -or
            ($row.FailureCode -isnot [long] -and $row.FailureCode -isnot [int]) -or
            $row.FailureCode -lt [int]::MinValue -or $row.FailureCode -gt [int]::MaxValue) { throw 'Invalid sanitized failure metadata.' }
        foreach ($key in @('Connections', 'Tls', 'Binds', 'Searches', 'Anonymous', 'Sasl', 'PrimaryBinds', 'PrimarySearches', 'Closed')) {
            if ($row[$key] -isnot [long] -and $row[$key] -isnot [int]) { throw 'Invalid numeric observation.' }
            if ($row[$key] -lt 0 -or $row[$key] -gt 10000) { throw 'Observation out of bounds.' }
        }
        if ($row.Status -eq 'passed') {
            $searches = if ($name -like '*retained-primary' -or $name -in @('a-to-b', 'b-to-a')) { 4 } else { 2 }
            if ($row.Connections -lt 2 -or $row.Tls -lt 2 -or $row.Binds -lt 2 -or
                $row.Searches -ne $searches -or $row.Anonymous -ne 0 -or $row.Sasl -ne 0 -or
                $row.Closed -ne $row.Connections) { throw 'Passing native observations incomplete.' }
            if ($name -notlike '*-direct' -and ($row.PrimaryBinds -ne 2 -or $row.PrimarySearches -ne $searches)) { throw 'Retained primary observations incomplete.' }
        }
    }
    foreach ($identity in @('original', 'a', 'b')) {
        if ($value["$identity-direct"].Status -ne 'passed' -and $value["$identity-referral"].Status -ne 'skipped') { throw 'Direct gate bypassed.' }
        if ($value["$identity-referral"].Status -ne 'passed' -and $value["$identity-retained-primary"].Status -ne 'skipped') { throw 'Referral gate bypassed.' }
    }
    if ($value['a-retained-primary'].Status -ne 'passed' -or $value['b-retained-primary'].Status -ne 'passed') {
        if ($value['a-to-b'].Status -ne 'skipped' -or $value['b-to-a'].Status -ne 'skipped') { throw 'Transition gate bypassed.' }
    }
    return $value
}
