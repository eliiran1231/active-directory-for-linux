$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Fixture-Core.ps1')
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
function Check($value, $message) { if (!$value) { throw $message } }
function MustThrow([scriptblock]$Run) {
    $failed = $false
    try { & $Run | Out-Null } catch { $failed = $true }
    Check $failed 'Expected failure did not occur.'
}
Check ((Get-DiagnosticNativeErrorCode ([ComponentModel.Win32Exception]::new(5, 'synthetic secret never printed'))) -eq 5) 'Native error sanitization failed.'

# Stage failures remain identity-local; sequential reads are not concurrent stress.
foreach ($failure in @('', 'a-direct', 'b-direct', 'original-direct', 'a-referral', 'a-retained-primary')) {
    $calls = [Collections.Generic.List[string]]::new()
    $results = Invoke-AuthenticatedStages { param($name) $calls.Add($name); $name -ne $failure }
    if ($failure -like 'a-*') {
        Check ($results['original-retained-primary'] -eq 'passed') 'A suppressed original stages.'
        Check ($results['b-retained-primary'] -eq 'passed') 'A suppressed B stages.'
        Check ($results['a-to-b'] -eq 'skipped') 'Cross-identity stage bypassed a dependency.'
    }
    if ($failure -eq 'original-direct') { Check ($results['a-to-b'] -eq 'passed') 'Original suppressed independent A/B stages.' }
}
$results = Invoke-AuthenticatedStages { param($name) if ($name -eq 'a-direct') { throw 'synthetic' }; $true }
Check ($results['b-retained-primary'] -eq 'passed') 'Thrown A failure suppressed B.'
Check ($results['a-referral'] -eq 'skipped') 'Thrown A failure did not gate A.'
$results = Invoke-AuthenticatedStages { 'not a Boolean' }
Check ($results['a-to-b'] -eq 'skipped') 'Invalid result permitted transition.'

# All operations below are fakes. No adapter file is loaded or called.
$sidA = 'S-1-5-21-1-2-3-1001'; $sidB = 'S-1-5-21-1-2-3-1002'
$state = New-AuthenticatedManifest
$saved = [Collections.Generic.List[string]]::new()
$counter = @{ Value = 0 }
$ops = @{
    Exists = { param($name) $false }
    Create = { param($name) $counter.Value++; if ($counter.Value -eq 2) { throw 'synthetic second create failure' }; $sidA }
}
MustThrow { Initialize-AuthenticatedAccounts $state { $saved.Add(($state | ConvertTo-Json -Depth 8 -Compress)) } $ops }
Check ($counter.Value -eq 2) 'Wrong partial creation point.'
Check ($state.Accounts[0].State -eq 'owned' -and $state.Accounts[0].Sid -eq $sidA) 'First SID not retained.'
Check ($state.Accounts[1].State -eq 'creating' -and !$state.Accounts[1].Sid) 'Uncertain second ownership invented.'
Check ($saved[0] -like '*planned*') 'No pre-mutation manifest.'
Check ($saved[2] -like "*$sidA*") 'SID not saved before second create.'

$calls = [Collections.Generic.List[string]]::new()
$remaining = @{ Value = $sidA }
$cleanup = @{
    StopWorker = { $calls.Add('stop') }
    FindSid = { param($name) $remaining.Value }
    RemoveAccount = { param($sid) $calls.Add($sid); $remaining.Value = $null }
    Certificate = { $calls.Add('certificate'); throw 'synthetic cert removal failure' }
    Pfx = { $calls.Add('pfx') }
}
$failures = Remove-AuthenticatedObjects $state $cleanup
Check ($calls[0] -eq 'stop' -and $calls.Contains($sidA)) 'Worker not stopped before owned cleanup.'
Check ($calls.Contains('pfx')) 'Certificate failure prevented PFX cleanup.'
Check ($failures.Count -eq 2) 'Unresolved account/certificate failure hidden.'

# SID mismatch and no-SID records never authorize deletion, but other cleanup runs.
$calls.Clear(); $remaining.Value = $sidB
$failures = Remove-AuthenticatedObjects $state $cleanup
Check (!$calls.Contains($sidA) -and !$calls.Contains($sidB)) 'Deleted mismatched identity.'
Check ($calls.Contains('certificate') -and $calls.Contains('pfx')) 'Mismatch suppressed independent cleanup.'
$calls.Clear(); $cleanup.StopWorker = { throw 'worker live' }
MustThrow { Remove-AuthenticatedObjects $state $cleanup }
Check ($calls.Count -eq 0) 'Cleanup raced live worker.'

# Preexisting account blocks all creation; no deletion ownership is recorded.
$state = New-AuthenticatedManifest; $counter.Value = 0
$ops.Exists = { param($name) $true }
MustThrow { Initialize-AuthenticatedAccounts $state { } $ops }
Check ($counter.Value -eq 0 -and $state.Accounts[0].State -eq 'planned') 'Preexisting account mutated.'

# Manifest save failure prevents creation. Exercise real durable file IO in temp only.
$ops.Exists = { param($name) $false }
MustThrow { Initialize-AuthenticatedAccounts $state { throw 'synthetic disk failure' } $ops }
Check ($counter.Value -eq 0) 'Mutation preceded durable intent.'
$path = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.json')
try {
    Save-AuthenticatedManifest $state $path
    $roundtrip = Read-AuthenticatedManifest $path
    Check ($roundtrip.Accounts[0].Name -eq $state.Accounts[0].Name) 'Manifest roundtrip failed.'
    Check (!(Test-Path "$path.new")) 'Atomic manifest temporary file remained.'
} finally { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }

# Failure while persisting a created SID must stop before the next account.
$state = New-AuthenticatedManifest; $counter.Value = 0
$ops.Create = { param($name) $counter.Value++; $sidA }
MustThrow { Initialize-AuthenticatedAccounts $state { if ($state.Accounts[0].State -eq 'owned') { throw 'SID save failed' } } $ops }
Check ($counter.Value -eq 1 -and $state.Accounts[0].Sid -eq $sidA) 'Lost in-memory ownership after SID-save failure.'
$calls.Clear(); $cleanup.StopWorker = { $calls.Add('stop') }
$cleanup.FindSid = { param($name) throw 'lookup unavailable' }
$failures = Remove-AuthenticatedObjects $state $cleanup
Check ($failures.Count -eq 2 -and !$calls.Contains($sidA)) 'Lookup error was treated as verified absence.'
Check ($calls.Contains('pfx')) 'Lookup error blocked other cleanup.'
$calls.Clear(); $cleanup.FindSid = { param($name) $sidA }
$cleanup.RemoveAccount = { param($sid) $calls.Add($sid) } # Deliberately leaves object present.
$failures = Remove-AuthenticatedObjects $state $cleanup
Check ($failures.Count -eq 2) 'Failed absence verification was hidden.'
$state.Password = 'synthetic forbidden field'
MustThrow { Assert-AuthenticatedManifest $state }
$state.Remove('Password')
$state.Accounts[0].Name = 'unrelated'
$calls.Clear()
$failures = Remove-AuthenticatedObjects $state $cleanup
Check ($failures.Contains('account-manifest') -and !$calls.Contains($sidA)) 'Invalid manifest authorized account deletion.'
Check ($calls.Contains('pfx') -and $calls.Contains('certificate')) 'Bad account manifest blocked independently owned cleanup.'

Check (Test-DiagnosticPrivateAccess 'runner' 'runner' @('runner', 'S-1-5-18', 'S-1-5-32-544')) 'Private directory rejected.'
Check (!(Test-DiagnosticPrivateAccess 'runner' 'runner' @('runner', 'S-1-5-32-545'))) 'Broad standard-user access accepted.'
Check (!(Test-DiagnosticPrivateAccess 'unrelated' 'runner' @('runner'))) 'Foreign directory owner accepted.'
Check (!(Test-DiagnosticPrivateAccess 'runner' 'runner' @())) 'Null/unrestricted DACL accepted.'

# Exercise the same handoff/lifecycle functions used by the executable adapter.
# Each injected failure must prevent release/next work and still stop/dispose.
foreach ($failure in @('', 'Start', 'Assign', 'CopyA', 'CopyB', 'Release', 'Wait', 'Read', 'StopAndVerify')) {
    $events = [Collections.Generic.List[string]]::new()
    $operations = @{}
    foreach ($step in @('Start', 'Assign', 'CopyA', 'CopyB', 'Release', 'Wait', 'Read', 'StopAndVerify', 'Dispose')) {
        $stepName = $step
        $operations[$step] = {
            param($context, $first, $second)
            $events.Add($stepName)
            if ($stepName -eq $failure) { throw 'synthetic private error must never be logged' }
            if ($stepName -eq 'Read') { return @{ Validated = $true } }
            if ($stepName -in @('CopyA', 'CopyB')) { return '123' }
        }.GetNewClosure()
    }
    if ($failure) { MustThrow { Invoke-DiagnosticRuntime $operations } }
    else { Check ((Invoke-DiagnosticRuntime $operations).Validated) 'Runtime result missing.' }
    Check ($events.Contains('StopAndVerify') -and $events[$events.Count - 1] -eq 'Dispose') 'Runtime cleanup skipped.'
    if ($failure -in @('Start', 'Assign', 'CopyA', 'CopyB')) { Check (!$events.Contains('Release')) 'Partial handoff released worker.' }
}
foreach ($failure in @('', 'Start', 'Assign', 'Release', 'WaitSetup', 'WaitComplete', 'Read', 'StopAndVerify', 'Cleanup')) {
    $events = [Collections.Generic.List[string]]::new(); $operations = @{}; $context = @{}
    foreach ($step in @('Start', 'Assign', 'Release', 'WaitSetup', 'WaitComplete', 'Read', 'StopAndVerify', 'Cleanup', 'Dispose')) {
        $stepName = $step
        $operations[$step] = {
            param($current, $milliseconds)
            $events.Add($stepName)
            # GetNewClosure captures variables, not the script-local Check function.
            if ($stepName -eq 'WaitSetup' -and $milliseconds -ne 60000) { throw 'Setup watchdog changed.' }
            if ($stepName -eq $failure) { throw [OperationCanceledException]::new('synthetic cancellation/death/timeout') }
            if ($stepName -eq 'Read') { return 0 }
        }.GetNewClosure()
    }
    if ($failure) { MustThrow { Invoke-DiagnosticSupervisor $operations $context } }
    else { Check ((Invoke-DiagnosticSupervisor $operations $context) -eq 0) 'Supervisor result missing.' }
    Check ($events[$events.Count - 1] -eq 'Dispose') 'Supervisor handles not disposed.'
    if ($failure -eq 'StopAndVerify') { Check (!$events.Contains('Cleanup')) 'Cleanup raced unconfirmed descendants.' }
    else { Check ($events.Contains('Cleanup')) 'Independent cleanup skipped after setup/runtime failure.' }
    if ($failure -in @('Start', 'Assign')) { Check (!$events.Contains('Release')) 'Unassigned coordinator released.' }
}

$result = @{}
foreach ($name in @('original-direct', 'original-referral', 'original-retained-primary', 'a-direct', 'a-referral', 'a-retained-primary',
    'b-direct', 'b-referral', 'b-retained-primary', 'a-to-b', 'b-to-a', 'anonymous-direct')) {
    $result[$name] = @{ Status = 'passed'; Connections = 2; Tls = 2; Binds = 2; Searches = 2; Anonymous = 0; Sasl = 0; PrimaryBinds = 0; PrimarySearches = 0; Closed = 2; Phase = 'complete'; FailureKind = 'none'; FailureCode = 0 }
    if ($name -notlike '*-direct') { $result[$name].PrimaryBinds = 2; $result[$name].PrimarySearches = 2 }
    if ($name -like '*retained-primary' -or $name -in @('a-to-b', 'b-to-a')) { $result[$name].Searches = 4; $result[$name].PrimarySearches = 4 }
}
$validated = ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8)
Check ($validated.Count -eq 12) 'Wrong native result count.'
$result['a-direct'].Tls = 0
MustThrow { ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8) }
$result['a-direct'].Tls = 2
$result.Password = 'synthetic-sensitive-output'
MustThrow { ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8) }
$result.Remove('Password')
$result['a-direct'].Status = 'failed'
MustThrow { ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8) }
$result['a-referral'].Status = 'skipped'; $result['a-retained-primary'].Status = 'skipped'
$result['a-to-b'].Status = 'skipped'; $result['b-to-a'].Status = 'skipped'
Check ((ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8))['b-referral'].Status -eq 'passed') 'Independent B result lost.'
$result['b-direct'].Binds = 'synthetic-secret'
MustThrow { ConvertTo-DiagnosticResult ($result | ConvertTo-Json -Depth 8) }

$appData = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'synthetic-appdata')
Check (Test-DiagnosticDirectoryAttributes $true $true ([IO.FileAttributes]::Directory)) 'Ordinary directory attributes rejected.'
Check (!(Test-DiagnosticDirectoryAttributes $false $true ([IO.FileAttributes]::Directory))) 'Missing directory accepted.'
Check (!(Test-DiagnosticDirectoryAttributes $true $false ([IO.FileAttributes]::Normal))) 'File accepted as directory.'
Check (!(Test-DiagnosticDirectoryAttributes $true $true ([IO.FileAttributes]::Normal))) 'Missing directory attribute accepted.'
Check (!(Test-DiagnosticDirectoryAttributes $true $true ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) 'Reparse directory accepted.'
# Traverse real CLR Parent objects, not just Get-Item's provider-enriched first object.
Assert-DiagnosticNoReparsePath $PSScriptRoot
MustThrow { Assert-DiagnosticNoReparsePath (Join-Path $PSScriptRoot 'Test-AuthenticatedFixture.ps1') }
MustThrow { Assert-DiagnosticNoReparsePath (Join-Path $PSScriptRoot ('absent-' + [Guid]::NewGuid().ToString('N'))) }
$runId = 'a' * 32
Check ((Get-DiagnosticRoot $appData $runId) -ceq [IO.Path]::Combine($appData, 'Temp', "adfl-auth-$runId")) 'Fixed private parent mismatch.'
MustThrow { Get-DiagnosticRoot '' $runId }
MustThrow { Get-DiagnosticRoot 'relative' $runId }
MustThrow { Get-DiagnosticRoot $appData '../escape' }
$permission = @{
    Candidate = 'process-temp'; Status = 'read'; Owner = 'runner'; AllowCount = 1; UnapprovedAllowCount = 0
    Canonical = $true; CurrentGuardPass = $true; DaclPresent = ($null -ne @(@{ Synthetic = 'never emit this object' }))
    InheritanceProtected = $false; OwnerApproved = $true; ReparsePoint = $false
    Rules = @(@{ Index = 0; Principal = 'runner'; Type = 'Allow'; Rights = [long]2032127; Inherited = $true;
        Inheritance = 3; Propagation = 0; ApprovedPrincipal = $true })
}
$safePermission = ConvertTo-DiagnosticPermissionJson $permission | ConvertFrom-Json
Check ($safePermission.DaclPresent -is [bool] -and $safePermission.DaclPresent) 'ACL collection did not become a scalar flag.'
foreach ($field in @('Canonical', 'CurrentGuardPass', 'DaclPresent', 'InheritanceProtected', 'OwnerApproved', 'ReparsePoint')) {
    $saved = $permission[$field]
    $permission[$field] = @(@{ SecurityIdentifier = 'synthetic-private-metadata' })
    MustThrow { ConvertTo-DiagnosticPermissionJson $permission }
    $permission[$field] = $saved
}
$permission.Rules[0].SecurityIdentifier = 'synthetic-private-metadata'
MustThrow { ConvertTo-DiagnosticPermissionJson $permission }
$permission.Rules[0].Remove('SecurityIdentifier')
$permission.DaclPresent = ($null -ne $null)
Check (!((ConvertTo-DiagnosticPermissionJson $permission | ConvertFrom-Json).DaclPresent)) 'Null ACL presence incorrectly reported.'

foreach ($file in @('Authenticated-Fixture-Core.ps1', 'Authenticated-Windows-Adapters.ps1', 'Authenticated-Integration.ps1', 'Authenticated-Fixture.ps1', 'Test-AuthenticatedFixture.ps1', 'Read-DirectoryPermissions.ps1', 'Authenticated-E2E-Adapters.ps1', 'Test-AuthenticatedEndToEnd.ps1')) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$errors) | Out-Null
    Check ($errors.Count -eq 0) "Parser failed: $file"
}
# Compile only. Never invoke Run or any native API (works on Linux preflight).
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Token.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'Authenticated-Process.cs')
Check ([AdflProcessJob]::ExtendedSize -eq 144 -and [AdflProcessJob]::AccountingSize -eq 48) 'x64 interop layout mismatch.'
Write-Host 'Authenticated helper pure tests, syntax and token bridge compilation passed; no Windows operations executed.'
