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
        if (($row.Keys | Sort-Object) -join ',' -cne 'Anonymous,BaselineCredentialed,Checks,Cleanup,CleanupMask,Closed,FailureCode,FailureKind,FailurePoint,KeyCleanupCode,LeaseCleanupCode,ManagedAttempts,ObservedFailureCode,ObservedFailureKind,OperationStarts,OtherCleanupCode,PoolDelta,PooledCredentialed,PrimaryBinds,Sasl,SourceAbandons,SourceCleanupCode,SourceOverlapArrivals,SourceOverlapTimeouts,Status,TargetAbandons,TargetBerPrefixes,TargetBinds,TargetCleanupCode,TargetConnections,TargetRejectedTlsProbes,TargetSearches,TargetTls,TargetTlsPrefixes,Timeline,TimelineDropped,WorkersReady') { throw 'Unexpected pool observation fields.' }
        if ($row.FailurePoint -notin @('none', 'setup', 'other', 'assertion', 'ambient-identity', 'concurrent-counts', 'search-shape', 'ldap-identity', 'native-response', 'native-operation', 'cleanup')) { throw 'Invalid fixed failure point.' }
        if ($row.Status -notin @('passed', 'failed', 'skipped') -or $row.Cleanup -isnot [bool]) { throw 'Invalid pool status.' }
        foreach ($field in @('FailureKind', 'ObservedFailureKind')) {
            if ($row[$field] -notin @('none', 'ldap', 'directory', 'fixture', 'response')) { throw 'Invalid pool failure kind.' }
        }
        foreach ($field in @('FailureCode', 'ObservedFailureCode', 'LeaseCleanupCode', 'KeyCleanupCode', 'OtherCleanupCode', 'SourceCleanupCode', 'TargetCleanupCode')) {
            if (($row[$field] -isnot [int] -and $row[$field] -isnot [long]) -or $row[$field] -lt [int]::MinValue -or $row[$field] -gt [int]::MaxValue) { throw 'Invalid pool failure code.' }
        }
        foreach ($field in @('Checks', 'PrimaryBinds', 'TargetConnections', 'TargetTls', 'TargetBinds', 'TargetSearches',
            'Anonymous', 'Sasl', 'Closed', 'ManagedAttempts', 'BaselineCredentialed', 'PooledCredentialed', 'SourceAbandons', 'TargetAbandons', 'TargetTlsPrefixes', 'TargetBerPrefixes', 'TargetRejectedTlsProbes', 'WorkersReady', 'OperationStarts', 'SourceOverlapArrivals', 'SourceOverlapTimeouts', 'TimelineDropped')) {
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
                $connections = @(); $lastArrival = 0; $firstRelease = [int]::MaxValue
                $lastEnter = 0; $firstExit = [int]::MaxValue
                foreach ($operation in @('1', '2')) {
                    $previous = 0; $sourceConnection = $null
                    foreach ($pair in @(@('client', 'native-enter'), @('source', 'search'), @('source', 'arrive'),
                        @('source', 'release'), @('source', 'referral-send'), @('target', 'search'),
                        @('target', 'response-send'), @('client', 'native-exit'))) {
                        $matching = @($events | Where-Object { $_[2] -ceq $pair[0] -and $_[5] -ceq $operation -and $_[6] -ceq $pair[1] })
                        if ($matching.Count -ne 1) { throw 'Missing or duplicate correlated operation.' }
                        $event = $matching[0]; $sequence = [int]$event[0]
                        if ($sequence -le $previous) { throw 'Invalid operation order.' }; $previous = $sequence
                        if ($pair[0] -ceq 'source') {
                            if ($null -eq $sourceConnection) { $sourceConnection = $event[3] }
                            if ($event[3] -ceq '0' -or $event[3] -cne $sourceConnection) { throw 'Source connection changed.' }
                        }
                        switch ($pair[1]) {
                            'arrive' { $lastArrival = [Math]::Max($lastArrival, $sequence) }
                            'release' { $firstRelease = [Math]::Min($firstRelease, $sequence) }
                            'native-enter' { $lastEnter = [Math]::Max($lastEnter, $sequence) }
                            'native-exit' { $firstExit = [Math]::Min($firstExit, $sequence) }
                        }
                    }
                    $connections += $sourceConnection
                }
                if ($connections[0] -ceq $connections[1] -or $lastArrival -ge $firstRelease -or $lastEnter -ge $firstExit) { throw 'Distinct primary operation overlap absent.' }
            }
            if ($name -like '*-concurrent' -and ($row.WorkersReady -ne 2 -or $row.OperationStarts -ne 2 -or
                $row.SourceOverlapArrivals -ne 2 -or $row.SourceOverlapTimeouts -ne 0 -or $row.TargetSearches -ne 2 -or $row.ManagedAttempts -ne 2)) { throw 'Concurrent operation evidence incomplete.' }
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

function Get-ContextCandidateNames {
    foreach ($identity in @('original', 'a', 'b')) {
        foreach ($scenario in @('stable', 'failed-bind', 'primary-failure', 'target-failure', 'findone')) { "$identity/$scenario" }
    }
    foreach ($identity in @('a-to-b', 'b-to-a', 'anonymous')) {
        foreach ($stage in @('acquired', 'send', 'complete', 'return')) { "$identity/$stage" }
    }
    'anonymous/first'; 'anonymous/repeated'; 'anonymous/primary'; 'partition/a-b-a'
}
function ConvertTo-ContextCandidateResult([string]$Json) {
    if ($Json.Length -gt 65536) { throw 'Candidate output limit exceeded.' }
    $value = $Json | ConvertFrom-Json -AsHashtable
    if (($value.Keys | Sort-Object) -join ',' -cne 'Adverse,AllPassed,Candidate,Native,Supported') { throw 'Unexpected candidate report.' }
    $native = ConvertTo-DiagnosticResult ($value.Native | ConvertTo-Json -Depth 8 -Compress)
    $names = @(Get-ContextCandidateNames)
    if (($value.Candidate.Keys | Sort-Object) -join ',' -cne (($names | Sort-Object) -join ',')) { throw 'Candidate cases missing or unexpected.' }
    foreach ($name in $names) {
        $row = $value.Candidate[$name]
        if (($row.Keys | Sort-Object) -join ',' -cne 'Attempts,Checks,Cleanup,FailureCode,FailureKind,FreshCode,FreshKind,InstrumentationFailed,ObservedCode,ObservedKind,PoolDelta,QueryCode,QueryKind,QueryStage,SourceBinds,SourceSearches,Status,TargetBinds,TargetSearches,WarmCode,WarmKind') { throw 'Unexpected candidate fields.' }
        if ($row.Status -notin @('passed', 'failed', 'skipped') -or $row.Cleanup -isnot [bool] -or $row.InstrumentationFailed -isnot [bool]) { throw 'Invalid candidate status.' }
        foreach ($field in @('Attempts', 'Checks', 'SourceBinds', 'SourceSearches', 'TargetBinds', 'TargetSearches', 'FailureCode', 'FreshCode', 'WarmCode', 'ObservedCode', 'PoolDelta', 'QueryCode')) {
            if (($row[$field] -isnot [int] -and $row[$field] -isnot [long]) -or $row[$field] -lt [int]::MinValue -or $row[$field] -gt [int]::MaxValue) { throw 'Invalid candidate number.' }
        }
        foreach ($field in @('Attempts', 'Checks', 'SourceBinds', 'SourceSearches', 'TargetBinds', 'TargetSearches')) {
            if ($row[$field] -lt 0 -or $row[$field] -gt 10000) { throw 'Invalid candidate counter.' }
        }
        foreach ($prefix in @('Failure', 'Fresh', 'Warm', 'Observed')) {
            if ($row[$prefix + 'Kind'] -notin @('success','ldap','directory','directory-no-response','fixture')) { throw 'Unexpected native outcome kind.' }
            if ($row[$prefix + 'Kind'] -eq 'success' -and $row[$prefix + 'Code'] -ne 0) { throw 'Success with failure code.' }
        }
        if ($row.QueryKind -notin @('none','rejected','win32','managed','length') -or
            $row.QueryStage -notin @('not-queried','guard','offline','platform','open-thread','open-process','statistics-before','statistics-before-length','restrictions','restrictions-length','restrictions-unwritten','restrictions-format','app-container','app-container-length','app-container-unwritten','app-container-format','token-user','token-user-length','token-user-read','token-user-read-length','token-user-complete','sid-bounds','statistics-after','statistics-after-length','token-changed','sid-unreadable','anonymous','restricted','app-container-token','token-id-unavailable','authentication-id-unavailable','modified-id-unavailable','token-type','impersonation-level','eligible')) { throw 'Unexpected query diagnostic.' }
        $owner = $name.Split('/')[0]
        $identities = if ($owner -in @('a-to-b','b-to-a','partition')) { @('a','b') } elseif ($owner -eq 'anonymous') { @('original') } else { @($owner) }
        $ready = $true
        foreach ($identity in $identities) { if ($native["$identity-direct"].Status -ne 'passed' -or $native["$identity-referral"].Status -ne 'passed') { $ready = $false } }
        if ((!$ready -and $row.Status -ne 'skipped') -or ($ready -and $row.Status -eq 'skipped')) { throw 'Candidate dependency mismatch.' }
        if ($row.Status -eq 'passed' -and (!$row.Cleanup -or $row.PoolDelta -ne 0 -or $row.InstrumentationFailed -or $row.FailureCode -ne 0 -or $row.FailureKind -ne 'success' -or $row.Checks -lt 1 -or $row.Attempts -lt 1)) { throw 'Incomplete candidate success.' }
        if ($row.Status -eq 'passed') {
            $scenario = $name.Split('/')[1]
            if ($scenario -eq 'stable' -and ($row.Attempts -ne 3 -or $row.SourceBinds -ne 1 -or $row.TargetSearches -ne 3)) { throw 'Stable reuse counters incomplete.' }
            if ($scenario -eq 'failed-bind' -and ($row.Attempts -ne 2 -or $row.ObservedCode -ne 49 -or $row.ObservedKind -ne 'ldap' -or $row.TargetSearches -ne 1)) { throw 'Bind rejection evidence incomplete.' }
            if ($scenario -in @('primary-failure','target-failure') -and ($row.Attempts -ne 3 -or $row.SourceBinds -lt 2 -or $row.ObservedKind -notin @('ldap','directory') -or $row.ObservedCode -notin @(2,52,81,82,85,91))) { throw 'Transport failure evidence incomplete.' }
            if ($scenario -eq 'findone' -and ($row.Attempts -ne 2 -or $row.SourceBinds -ne 3 -or $row.SourceSearches -ne 6 -or $row.TargetSearches -ne 2)) { throw 'FindOne/schema evidence incomplete.' }
            if ($owner -in @('a-to-b','b-to-a') -and ($row.Attempts -ne 1 -or $row.SourceSearches -ne 1 -or $row.TargetSearches -ne 1)) { throw 'Transition evidence incomplete.' }
            if ($owner -eq 'partition' -and ($row.Attempts -ne 3 -or $row.SourceBinds -ne 2 -or $row.TargetSearches -ne 3)) { throw 'Partition evidence incomplete.' }
            if ($owner -eq 'anonymous' -and $scenario -in @('complete','return') -and ($row.Attempts -ne 1 -or $row.TargetSearches -ne 1)) { throw 'Post-send anonymous evidence incomplete.' }
            if ($owner -eq 'anonymous' -and $scenario -notin @('complete','return') -and ($row.FreshKind -ne $row.WarmKind -or $row.FreshCode -ne $row.WarmCode -or $row.Attempts -ne $(if ($scenario -in @('acquired','send')) { 2 } else { 3 }))) { throw 'Anonymous parity evidence incomplete.' }
        }
    }
    $supported = @($native.GetEnumerator() | Where-Object { $_.Key -ne 'anonymous-direct' -and $_.Value.Status -ne 'passed' }).Count -eq 0 -and @($value.Candidate.Values | Where-Object Status -NE 'passed').Count -eq 0
    $adverse = $native['anonymous-direct'].Status -eq 'passed'
    if ($value.Supported -cne $(if ($supported) { 'passed' } else { 'failed' }) -or $value.Adverse -cne $(if ($adverse) { 'passed' } else { 'failed' }) -or $value.AllPassed -isnot [bool] -or $value.AllPassed -ne ($supported -and $adverse)) { throw 'Candidate verdict mismatch.' }
    return $value
}

function ConvertTo-ContextQueryResult([string]$Json) {
    if ($Json.Length -gt 4096) { throw 'Token query report too large.' }
    $row = $Json | ConvertFrom-Json -AsHashtable
    if (($row.Keys | Sort-Object) -join ',' -cne 'Eligible,FirstCode,FirstKind,FirstStage,FixedEligible,FixedFirstCode,FixedFirstKind,FixedFirstStage,FixedSecondCode,FixedSecondKind,FixedSecondStage,FixedStable,SecondCode,SecondKind,SecondStage,Stable') { throw 'Unexpected token query fields.' }
    foreach ($field in @('Eligible','Stable','FixedEligible','FixedStable')) {
        if ($row[$field] -isnot [bool]) { throw 'Invalid query boolean.' }
    }
    foreach ($prefix in @('First','Second','FixedFirst','FixedSecond')) {
        if ($row[$prefix + 'Stage'] -notin @('guard','offline','platform','open-thread','open-process','statistics-before','statistics-before-length','restrictions','restrictions-length','restrictions-format','app-container','app-container-length','app-container-format','token-user','token-user-length','token-user-read','token-user-read-length','token-user-complete','sid-bounds','statistics-after','statistics-after-length','token-changed','sid-unreadable','anonymous','restricted','app-container-token','token-id-unavailable','authentication-id-unavailable','modified-id-unavailable','token-type','impersonation-level','eligible') -or
            $row[$prefix + 'Kind'] -notin @('none','rejected','win32','managed','length') -or
            ($row[$prefix + 'Code'] -isnot [int] -and $row[$prefix + 'Code'] -isnot [long]) -or
            $row[$prefix + 'Code'] -lt [int]::MinValue -or $row[$prefix + 'Code'] -gt [int]::MaxValue) { throw 'Invalid fixed query metadata.' }
    }
    foreach ($prefix in @('','Fixed')) {
        $eligible = $row[$prefix + 'FirstStage'] -eq 'eligible' -and $row[$prefix + 'SecondStage'] -eq 'eligible'
        if ($row[$prefix + 'Eligible'] -ne $eligible -or ($row[$prefix + 'Stable'] -and !$eligible)) { throw 'Inconsistent query verdict.' }
        if ($eligible -and ($row[$prefix + 'FirstKind'] -ne 'none' -or $row[$prefix + 'SecondKind'] -ne 'none' -or $row[$prefix + 'FirstCode'] -ne 0 -or $row[$prefix + 'SecondCode'] -ne 0)) { throw 'Eligible query contains a failure.' }
    }
    return $row
}
