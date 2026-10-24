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
function Get-DiagnosticRoot([string]$LocalAppData, [string]$RunId) {
    if (!$LocalAppData -or ![IO.Path]::IsPathFullyQualified($LocalAppData) -or $RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Invalid fixed diagnostic location.'
    }
    return [IO.Path]::GetFullPath([IO.Path]::Combine($LocalAppData, 'Temp', "adfl-auth-$RunId"))
}
function Test-DiagnosticDirectoryAttributes([bool]$Exists, [bool]$IsDirectory, [IO.FileAttributes]$Attributes) {
    return ($Exists -and $IsDirectory -and (($Attributes -band [IO.FileAttributes]::Directory) -ne 0) -and
        (($Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0))
}
function Assert-DiagnosticNoReparsePath([string]$Path) {
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        # DirectoryInfo.Parent is a CLR object without PowerShell's PSIsContainer property.
        $current.Refresh()
        if (!(Test-DiagnosticDirectoryAttributes $current.Exists ($current -is [IO.DirectoryInfo]) $current.Attributes)) {
            throw 'Diagnostic path must contain only existing ordinary directories.'
        }
        $current = $current.Parent
    }
}
function ConvertTo-DiagnosticPermissionJson($Value) {
    $keys = 'AllowCount,Candidate,Canonical,CurrentGuardPass,DaclPresent,InheritanceProtected,Owner,OwnerApproved,ReparsePoint,Rules,Status,UnapprovedAllowCount'
    if (($Value.Keys | Sort-Object) -join ',' -cne $keys) { throw 'Unexpected permission fields.' }
    if ($Value.Candidate -isnot [string] -or $Value.Status -isnot [string] -or
        $Value.Candidate -notin @('runner-temp', 'process-temp', 'runner-profile', 'local-appdata', 'local-appdata-temp', 'workspace') -or
        $Value.Status -cne 'read') { throw 'Invalid permission context.' }
    $categories = @('runner', 'system', 'administrators', 'standard-users', 'authenticated-users', 'everyone', 'creator-owner', 'creator-group', 'owner-rights', 'other')
    if ($Value.Owner -isnot [string] -or $Value.Owner -notin $categories) { throw 'Invalid owner category.' }
    foreach ($field in @('Canonical', 'CurrentGuardPass', 'DaclPresent', 'InheritanceProtected', 'OwnerApproved', 'ReparsePoint')) {
        if ($Value[$field] -isnot [bool]) { throw 'Non-scalar permission flag withheld.' }
    }
    foreach ($field in @('AllowCount', 'UnapprovedAllowCount')) {
        if ($Value[$field] -isnot [int] -or $Value[$field] -lt 0 -or $Value[$field] -gt 64) { throw 'Invalid permission count.' }
    }
    if ($Value.Rules -isnot [array] -or $Value.Rules.Count -gt 64) { throw 'Invalid permission rules.' }
    foreach ($row in $Value.Rules) {
        if (($row.Keys | Sort-Object) -join ',' -cne 'ApprovedPrincipal,Index,Inheritance,Inherited,Principal,Propagation,Rights,Type' -or
            $row.Principal -isnot [string] -or $row.Type -isnot [string] -or
            $row.Principal -notin $categories -or $row.Type -notin @('Allow', 'Deny') -or
            $row.ApprovedPrincipal -isnot [bool] -or $row.Inherited -isnot [bool]) { throw 'Invalid permission rule.' }
        foreach ($field in @('Index', 'Inheritance', 'Propagation')) {
            if ($row[$field] -isnot [int] -or $row[$field] -lt 0 -or $row[$field] -gt 64) { throw 'Invalid permission rule flags.' }
        }
        if ($row.Rights -isnot [long] -or $row.Rights -lt [int]::MinValue -or $row.Rights -gt [uint32]::MaxValue) { throw 'Invalid permission mask.' }
    }
    return ($Value | ConvertTo-Json -Depth 5 -Compress)
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

function Get-DiagnosticPoolCases {
    return @('isolation', 'concurrent', 'unpooled-concurrent', 'capacity', 'generation', 'failed-bind', 'primary-disconnect',
        'target-disconnect', 'target-bind-rejection', 'untrusted-target', 'mixed-referral')
}
function ConvertTo-DiagnosticCombinedResult([string]$Json) {
    if ($Json.Length -gt 65536) { throw 'Combined output limit exceeded.' }
    $value = $Json | ConvertFrom-Json -AsHashtable
    if (($value.Keys | Sort-Object) -join ',' -cne 'Adverse,AllPassed,Native,Pool,Supported') { throw 'Unexpected combined result fields.' }
    $native = ConvertTo-DiagnosticResult ($value.Native | ConvertTo-Json -Depth 8 -Compress)
    $names = @()
    foreach ($identity in @('original', 'a', 'b')) {
        foreach ($case in (Get-DiagnosticPoolCases)) { $names += "$identity-$case" }
    }
    $names += @('a-to-b', 'b-to-a', 'first-a-to-b', 'first-b-to-a')
    if (($value.Pool.Keys | Sort-Object) -join ',' -cne (($names | Sort-Object) -join ',')) { throw 'Unexpected pool cases.' }
    foreach ($name in $names) {
        $row = $value.Pool[$name]
        if (($row.Keys | Sort-Object) -join ',' -cne 'Anonymous,BaselineCredentialed,Checks,Cleanup,CleanupMask,Closed,FailureCode,FailureKind,FailurePoint,KeyCleanupCode,LeaseCleanupCode,ManagedAttempts,ObservedFailureCode,ObservedFailureKind,OperationStarts,OtherCleanupCode,OverlapArrivals,OverlapTimeouts,PoolDelta,PooledCredentialed,PrimaryBinds,Sasl,SourceAbandons,SourceCleanupCode,Status,TargetAbandons,TargetBerPrefixes,TargetBinds,TargetCleanupCode,TargetConnections,TargetRejectedTlsProbes,TargetSearches,TargetTls,TargetTlsPrefixes,Timeline,TimelineDropped,WorkersReady') { throw 'Unexpected pool observation fields.' }
        if ($row.FailurePoint -notin @('none', 'setup', 'other', 'assertion', 'ambient-identity', 'concurrent-counts', 'search-shape', 'ldap-identity', 'native-response', 'native-operation', 'cleanup')) { throw 'Invalid fixed failure point.' }
        if ($row.Status -notin @('passed', 'failed', 'skipped') -or $row.Cleanup -isnot [bool]) { throw 'Invalid pool status.' }
        foreach ($field in @('FailureKind', 'ObservedFailureKind')) {
            if ($row[$field] -notin @('none', 'ldap', 'directory', 'fixture', 'response')) { throw 'Invalid pool failure kind.' }
        }
        foreach ($field in @('FailureCode', 'ObservedFailureCode', 'LeaseCleanupCode', 'KeyCleanupCode', 'OtherCleanupCode', 'SourceCleanupCode', 'TargetCleanupCode')) {
            if (($row[$field] -isnot [int] -and $row[$field] -isnot [long]) -or $row[$field] -lt [int]::MinValue -or $row[$field] -gt [int]::MaxValue) { throw 'Invalid pool failure code.' }
        }
        foreach ($field in @('Checks', 'PrimaryBinds', 'TargetConnections', 'TargetTls', 'TargetBinds', 'TargetSearches',
            'Anonymous', 'Sasl', 'Closed', 'ManagedAttempts', 'BaselineCredentialed', 'PooledCredentialed', 'SourceAbandons', 'TargetAbandons', 'TargetTlsPrefixes', 'TargetBerPrefixes', 'TargetRejectedTlsProbes', 'WorkersReady', 'OperationStarts', 'OverlapArrivals', 'OverlapTimeouts', 'TimelineDropped')) {
            if (($row[$field] -isnot [int] -and $row[$field] -isnot [long]) -or $row[$field] -lt 0 -or $row[$field] -gt 10000) { throw 'Invalid pool counter.' }
        }
        if (($row.CleanupMask -isnot [int] -and $row.CleanupMask -isnot [long]) -or $row.CleanupMask -lt 0 -or $row.CleanupMask -gt 63 -or
            ($row.PoolDelta -isnot [int] -and $row.PoolDelta -isnot [long]) -or $row.PoolDelta -lt -10000 -or $row.PoolDelta -gt 10000) { throw 'Invalid cleanup attribution.' }
        foreach ($pair in @(@('LeaseCleanupCode', 1), @('KeyCleanupCode', 2), @('OtherCleanupCode', 4), @('SourceCleanupCode', 8), @('TargetCleanupCode', 16))) {
            if (($row.CleanupMask -band $pair[1]) -eq 0 -and $row[$pair[0]] -ne 0) { throw 'Cleanup code without category.' }
        }
        if (($row.PoolDelta -ne 0) -ne (($row.CleanupMask -band 32) -ne 0) -or
            ($row.Cleanup -and $row.CleanupMask -ne 0)) { throw 'Cleanup verdict inconsistent.' }
        if ($row.Timeline -isnot [string] -or $row.Timeline.Length -gt 8192) { throw 'Invalid timeline size.' }
        $events = @()
        if ($row.Timeline.Length -ne 0) {
            $lines = $row.Timeline.Split(';')
            if ($lines.Count -gt 64) { throw 'Too many timeline events.' }
            $sequence = 0; [long]$previousTime = 0
            foreach ($line in $lines) {
                if ($line -cnotmatch '^[0-9]{1,2}:[0-9]{1,12}:(client|source|target):[0-9]{1,10}:[0-9]{1,10}:[0-2]:(accept|tls|bind|search|referral-send|response-send|arrive|release|timeout|close|fault|native-enter|native-exit|native-error)$') { throw 'Invalid fixed timeline event.' }
                $fields = $line.Split(':'); $sequence++
                if ([int]$fields[0] -ne $sequence -or [long]$fields[1] -lt $previousTime -or
                    [long]$fields[3] -gt [int]::MaxValue -or [long]$fields[4] -gt [int]::MaxValue) { throw 'Invalid event ordering or ID.' }
                $previousTime = [long]$fields[1]
                $events += ,$fields
            }
        }
        if ($name -notlike '*-concurrent' -and ($events.Count -ne 0 -or $row.TimelineDropped -ne 0)) { throw 'Unexpected timeline scope.' }
        $identities = if ($name -match '^(first-)?[ab]-to-[ab]$') { @('a', 'b') } else { @($name.Split('-')[0]) }
        $ready = $true
        foreach ($identity in $identities) {
            if ($native["$identity-direct"].Status -ne 'passed' -or $native["$identity-referral"].Status -ne 'passed') { $ready = $false }
        }
        if ((!$ready -and $row.Status -ne 'skipped') -or ($ready -and $row.Status -eq 'skipped')) { throw 'Pool native dependency bypassed.' }
        if ($row.Status -eq 'passed') {
            if (!$row.Cleanup -or $row.Checks -lt 3 -or $row.PrimaryBinds -lt 1 -or $row.ManagedAttempts -lt 1 -or
                $row.Closed -ne $row.TargetConnections -or $row.Sasl -ne 0 -or $row.FailureKind -ne 'none' -or $row.FailureCode -ne 0 -or $row.FailurePoint -ne 'none') { throw 'Incomplete passing pool evidence.' }
            if ($name -notlike '*-mixed-referral' -and $row.Anonymous -ne 0) { throw 'Unexpected anonymous forwarding.' }
            if ($name -like '*-untrusted-target') {
                if ($row.TargetConnections -lt 1 -or $row.TargetBinds -ne 0 -or $row.TargetSearches -ne 0 -or $row.ObservedFailureKind -eq 'none') { throw 'Untrusted target evidence incomplete.' }
            } elseif ($name -like '*-target-bind-rejection') {
                if ($row.TargetTls -lt 1 -or $row.TargetBinds -lt 1 -or $row.TargetSearches -ne 0 -or $row.ObservedFailureKind -eq 'none') { throw 'Rejected target evidence incomplete.' }
            } elseif ($name -notlike '*-mixed-referral' -and ($row.TargetTls -lt 1 -or $row.TargetSearches -lt 1)) { throw 'Native pool search evidence absent.' }
            if ($name -like '*-concurrent') {
                if ($row.TimelineDropped -ne 0 -or @($events | Where-Object { $_[6] -in @('timeout', 'fault', 'native-error') }).Count -ne 0) { throw 'Incomplete or failed timeline.' }
                foreach ($operation in @('1', '2')) {
                    foreach ($pair in @(@('client', 'native-enter'), @('client', 'native-exit'), @('source', 'search'),
                        @('target', 'search'), @('target', 'arrive'), @('target', 'release'), @('target', 'response-send'))) {
                        if (@($events | Where-Object { $_[2] -ceq $pair[0] -and $_[5] -ceq $operation -and $_[6] -ceq $pair[1] }).Count -ne 1) { throw 'Missing or duplicate correlated operation.' }
                    }
                }
            }
            if ($name -like '*-concurrent' -and ($row.WorkersReady -ne 2 -or $row.OperationStarts -ne 2 -or
                $row.OverlapArrivals -ne 2 -or $row.OverlapTimeouts -ne 0 -or $row.TargetSearches -ne 2 -or $row.ManagedAttempts -ne 2)) { throw 'Concurrent operation evidence incomplete.' }
            if ($name -like '*-mixed-referral' -and $row.TargetRejectedTlsProbes -ne $row.TargetTlsPrefixes) { throw 'Protocol rejection evidence inconsistent.' }
            if ($name -like '*-disconnect' -and ($row.ManagedAttempts -ne 3 -or $row.ObservedFailureKind -eq 'none')) { throw 'Failure/replay evidence incomplete.' }
        }
    }
    $supported = @($native.Keys | Where-Object { $_ -ne 'anonymous-direct' -and $native[$_].Status -ne 'passed' }).Count -eq 0 -and
        @($value.Pool.Values | Where-Object Status -NE 'passed').Count -eq 0
    $adverse = $native['anonymous-direct'].Status -eq 'passed'
    if ($value.Supported -cne $(if ($supported) { 'passed' } else { 'failed' }) -or
        $value.Adverse -cne $(if ($adverse) { 'passed' } else { 'failed' }) -or
        $value.AllPassed -isnot [bool] -or $value.AllPassed -ne ($supported -and $adverse)) { throw 'Inconsistent diagnostic verdict.' }
    return $value
}
