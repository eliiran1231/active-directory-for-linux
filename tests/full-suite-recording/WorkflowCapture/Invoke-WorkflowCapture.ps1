#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Build','Run','Summarize')][string]$Action,
    [ValidateSet('net10.0-windows','net8.0-windows')][string]$Framework = 'net10.0-windows'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$policy = 'reviewed-live-lab-scalars-v1'
function HashFile([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function HashText([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
}
function WriteUtf8([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function NoReparse([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe path.' }
        $item=if ($item -is [IO.FileInfo]) {$item.Directory} else {$item.Parent}
    }
}
function PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'Existing output refused.' }
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($owner); $acl.SetAccessRuleProtection($true,$false)
    $allowedSids=@(@($owner.Value,'S-1-5-18') | Select-Object -Unique)
    foreach ($sidValue in $allowedSids) {
        $sid=[Security.Principal.SecurityIdentifier]::new($sidValue)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    }
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    NoReparse $Path
    $actual=Get-Acl -LiteralPath $Path
    $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner.Value -or $rules.Count -ne $allowedSids.Count) { throw 'Private ACL verification failed.' }
    foreach ($sid in $allowedSids) {
        $r=@($rules | Where-Object {$_.IdentityReference.Value -eq $sid})
        if ($r.Count -ne 1 -or $r[0].IsInherited -or $r[0].AccessControlType -ne 'Allow' -or $r[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $r[0].InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' -or $r[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'Unexpected ACL.' }
    }
}
function RequireRoot {
    if ([string]::IsNullOrWhiteSpace($env:ADFL_WORKFLOW_CAPTURE_ROOT)) { throw 'Missing capture root.' }
    NoReparse $env:ADFL_WORKFLOW_CAPTURE_ROOT
    return $env:ADFL_WORKFLOW_CAPTURE_ROOT
}
function UniqueJsonKeys([string]$Text) {
    # JSON writer emits plain property names. Reject escaped keys and duplicates,
    # before PowerShell 5.1 ConvertFrom-Json can collapse duplicate members.
    $tokens=[regex]::Matches($Text,'"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null')
    $stack=[Collections.Generic.Stack[object]]::new(); $position=0
    for ($i=0; $i -lt $tokens.Count; $i++) {
        $t=$tokens[$i]
        if ($Text.Substring($position,$t.Index-$position) -match '\S') {throw 'Invalid JSON token.'}
        $position=$t.Index+$t.Length
        switch ($t.Value) {
            '{' { $stack.Push([Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)) }
            '[' { $stack.Push($null) }
            '}' { if ($stack.Count -eq 0) {throw 'Invalid nesting.'}; [void]$stack.Pop() }
            ']' { if ($stack.Count -eq 0) {throw 'Invalid nesting.'}; [void]$stack.Pop() }
            default {
                if ($t.Value.StartsWith('"') -and $i+1 -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
                    if ($t.Value.Contains('\') -or $stack.Count -eq 0 -or $null -eq $stack.Peek()) {throw 'Invalid property name.'}
                    if (-not $stack.Peek().Add($t.Value)) {throw 'Duplicate JSON property.'}
                }
            }
        }
    }
    if ($stack.Count -ne 0 -or $Text.Substring($position) -match '\S') {throw 'Invalid JSON envelope.'}
}
function Scalar($Snapshot) {
    if ($null -eq $Snapshot -or $Snapshot.replayable -ne $true) { return $null }
    $type=[string]$Snapshot.type; $value=$Snapshot.value
    if ($type -eq 'null' -and $null -eq $value) { return @{type='null';value=$null} }
    if ($type -eq 'boolean' -and $value -is [bool]) { return @{type=$type;value=$value} }
    if ($type -in @('uint8','int8','int16','uint16','int32','uint32','int64','uint64','enum-int64','enum-uint64') -and
        ($value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64])) {
        return @{type=$type;value=$value}
    }
    # Exact finite names only. Never forward arbitrary strings, messages or type names.
    if ($type -eq 'exception-type' -and $value -is [string] -and $script:exceptionNames.Contains($value)) { return @{type=$type;value=$value} }
    return $null
}
$exceptionNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @('System.ArgumentException','System.ArgumentNullException','System.ArgumentOutOfRangeException','System.InvalidOperationException','System.ObjectDisposedException','System.NotSupportedException','System.NotImplementedException','System.NullReferenceException','System.IndexOutOfRangeException','System.InvalidCastException','System.FormatException','System.OverflowException','System.ComponentModel.InvalidEnumArgumentException','System.Runtime.InteropServices.COMException','System.Exception','System.DirectoryServices.DirectoryServicesCOMException','System.DirectoryServices.AccountManagement.PrincipalOperationException','System.DirectoryServices.AccountManagement.PrincipalServerDownException','System.DirectoryServices.AccountManagement.MultipleMatchesException','System.DirectoryServices.AccountManagement.NoMatchingPrincipalException','System.DirectoryServices.AccountManagement.PasswordException')) {
    [void]$exceptionNames.Add($name); [void]$exceptionNames.Add($name.Substring($name.LastIndexOf('.')+1))
}
try {
    if ($Action -eq 'Prepare') {
        if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($env:RUNNER_TEMP)).DriveType -ne [IO.DriveType]::Fixed) { throw 'Fixed local drive required.' }
        NoReparse $env:RUNNER_TEMP
        $root=Join-Path $env:RUNNER_TEMP ('adfl-private-capture-'+[Guid]::NewGuid().ToString('N'))
        PrivateDirectory $root
        foreach ($tfm in @('net10.0-windows','net8.0-windows')) {
            $dir=Join-Path $root $tfm; PrivateDirectory $dir
            PrivateDirectory (Join-Path $dir 'capture'); PrivateDirectory (Join-Path $dir 'trx')
        }
        # Hash only Git-tracked source/build inputs, never arbitrary local secret files.
        $head=(& git rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -ne 0 -or $head -cne $env:GITHUB_SHA) { throw 'Source revision mismatch.' }
        $files=@(& git ls-files -- '*.cs' '*.csproj' '*.props' '*.targets' '*.sln' 'global.json' 'NuGet.Config' 'nuget.config' 2>$null)
        if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) { throw 'Source inventory failed.' }
        [string[]]$lines=@($files | ForEach-Object { NoReparse $_; $_ + [char]0 + (HashFile $_) + "`n" })
        [Array]::Sort($lines,[StringComparer]::Ordinal)
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join ''))))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
        WriteUtf8 (Join-Path $root 'source.json') (@{schemaVersion=1;commit=$head;sourceTreeSha256=$hash;hashScope='git-tracked-cs-csproj-props-targets-sln-global-nuget'} | ConvertTo-Json -Compress)
        Add-Content -LiteralPath $env:GITHUB_ENV -Value ('ADFL_WORKFLOW_CAPTURE_ROOT='+$root) -Encoding utf8
        [Console]::WriteLine('Capture preparation complete. Raw files remain private on the runner.')
        exit 0
    }
    $root=RequireRoot
    if ($Action -eq 'Build') {
        # Existing solution restore occurs before this step. No new credential inputs.
        $ErrorActionPreference='Continue'
        & dotnet build tests/AdForLinux.DifferentialTests --configuration Release --no-restore 1>(Join-Path $root 'build.stdout.log') 2>(Join-Path $root 'build.stderr.log')
        $code=$LASTEXITCODE; $ErrorActionPreference='Stop'
        if ($code -ne 0) { throw 'Build failed.' }
        [Console]::WriteLine('Capture build complete for both original Windows targets.')
        exit 0
    }
    $dir=Join-Path $root $Framework
    if ($Action -eq 'Run') {
        foreach ($name in @('AD_HOST','AD_PORT','AD_USE_TLS','AD_BIND_DN','AD_BIND_PW','AD_BASE_DN')) {
            if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw 'Explicit workflow AD inputs required.' }
        }
        if ($env:AD_PORT -ne '636' -or $env:AD_USE_TLS -cne 'true' -or $env:AD_BASE_DN -notmatch '^OU=') { throw 'Explicit isolated TLS lab required.' }
        foreach ($name in @('AD_SECOND_HOST','AD_SECOND_BASE_DN','AD_SECOND_BIND_DN','AD_SECOND_BIND_PW','ADFL_OFFLINE_TESTS')) {
            if ([Environment]::GetEnvironmentVariable($name)) { throw 'Unexpected secondary/offline scope.' }
        }
        if ($env:AD_USERS_CONTAINER_DN -and $env:AD_USERS_CONTAINER_DN -cne $env:AD_BASE_DN) { throw 'Unexpected principal container.' }
        $env:AD_USERS_CONTAINER_DN=$env:AD_BASE_DN
        $source=Get-Content -LiteralPath (Join-Path $root 'source.json') -Raw | ConvertFrom-Json
        $assembly=Join-Path (Get-Location).Path "tests/AdForLinux.DifferentialTests/bin/Release/$Framework/AdForLinux.DifferentialTests.dll"
        NoReparse $assembly
        $review=Join-Path $dir 'review.json'
        WriteUtf8 $review (@{schemaVersion=1;capturePolicy=$policy;privacyScope='isolated-lab-scalar-values-reviewed';sourceTreeSha256=$source.sourceTreeSha256;assemblySha256=(HashFile $assembly)} | ConvertTo-Json -Compress)
        $env:ADFL_SUITE_CAPTURE_DIRECTORY=Join-Path $dir 'capture'
        $env:ADFL_SUITE_CAPTURE_MODE=$policy
        $env:ADFL_SUITE_CAPTURE_REVIEW_FILE=$review
        # Keep the same project, framework, tests, fixtures and assertions. Only output changes.
        $ErrorActionPreference='Continue'
        & dotnet test tests/AdForLinux.DifferentialTests -f $Framework --configuration Release --no-build --no-restore --logger 'trx;LogFileName=differential.trx' --results-directory (Join-Path $dir 'trx') 1>(Join-Path $dir 'tests.stdout.log') 2>(Join-Path $dir 'tests.stderr.log')
        $code=$LASTEXITCODE; $ErrorActionPreference='Stop'
        WriteUtf8 (Join-Path $dir 'exit.json') (@{testExitCode=$code;cleanup='unverified-fixture-best-effort'} | ConvertTo-Json -Compress)
        if ($code -ne 0) { [Console]::WriteLine('Original differential suite failed; private diagnostics retained.'); exit 1 }
        [Console]::WriteLine('Original differential suite returned zero; cleanup and capture completeness remain unverified.')
        exit 0
    }
    # No raw file contents or exceptions are ever printed by this exporter.
    $review=Get-Content -LiteralPath (Join-Path $dir 'review.json') -Raw | ConvertFrom-Json
    $source=Get-Content -LiteralPath (Join-Path $root 'source.json') -Raw | ConvertFrom-Json
    if ($source.commit -cnotmatch '^[a-f0-9]{40}$' -or $review.sourceTreeSha256 -cnotmatch '^[a-f0-9]{64}$' -or $review.assemblySha256 -cnotmatch '^[a-f0-9]{64}$' -or $review.capturePolicy -cne $policy -or $review.privacyScope -cne 'isolated-lab-scalar-values-reviewed') {throw 'Invalid review metadata.'}
    $counts=@{files=0;observations=0;explicitPairs=0;unverifiedOperands=0;redactedOrUnsupported=0;malformed=0;incomplete=0}
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $dir 'capture') -Filter '*.jsonl' -File) {
        NoReparse $file.FullName; $counts.files++
        $records=@(); $valid=$true; $execution=$null; $testMethod=$null; $state='begin'; $sequence=0
        if ($file.Length -gt 67108864) {$counts.malformed++; continue}
        # Validate complete ordered envelope before emitting any values from this execution.
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            try {
                if ($line.Length -gt 1048576) {throw 'Oversized record.'}
                UniqueJsonKeys $line
                $r=ConvertFrom-Json -InputObject $line
                if ($r.schemaVersion -ne 1 -or $r.execution -notmatch '^[a-f0-9]{32}$') {throw 'Schema mismatch.'}
                if ($state -ne 'begin' -and $r.execution -cne $execution) {throw 'Execution mismatch.'}
                switch ($r.kind) {
                    'begin' {
                        if ($state -ne 'begin') {throw 'Unexpected begin.'}
                        $execution=$r.execution; $testMethod=$r.testMethod
                        if ($testMethod -cnotmatch '^AdForLinux\.DifferentialTests\.[A-Za-z_][A-Za-z0-9_+`]*\.[A-Za-z_][A-Za-z0-9_]*$' -or $testMethod.Length -gt 512) {throw 'Invalid source method metadata.'}
                        if ($r.source -cne 'existing-windows-differential-suite' -or $r.provenance.capturePolicy -cne $policy -or $r.provenance.assemblySha256 -cne $review.assemblySha256) {throw 'Policy mismatch.'}
                        $state='review'
                    }
                    'live-scalar-review' {
                        if ($state -ne 'review' -or $r.capturePolicy -cne $policy -or $r.privacyScope -cne $review.privacyScope -or $r.sourceTreeSha256 -cne $review.sourceTreeSha256 -or $r.assemblySha256 -cne $review.assemblySha256 -or $r.sourcePinVerification -cne 'wrapper-attested-not-runtime-source-verification' -or $r.replayEligibility -cne 'unverified-no-automatic-promotion') {throw 'Review mismatch.'}
                        $state='observations'
                    }
                    'observation' {
                        if ($state -ne 'observations' -or $r.sequence -ne ($sequence+1) -or $r.origin -cnotin @('explicit-microsoft-comparison','assertion-operand-unverified')) {throw 'Invalid observation.'}
                        if ($r.sourceFile -cnotmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,200}\.cs$' -or
                            ($r.sourceMember -cnotin @('.ctor','.cctor') -and $r.sourceMember -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,300}$') -or
                            $r.sourceLine -isnot [int] -or $r.sourceLine -le 0 -or $r.sourceLine -gt 1000000 -or
                            $r.role -cnotin @('value','ordinal-ignore-case-set','assert-equal-expected','assert-equal-actual')) {throw 'Invalid source site metadata.'}
                        if (-not (Test-Path -LiteralPath (Join-Path 'tests/AdForLinux.DifferentialTests' $r.sourceFile) -PathType Leaf)) {throw 'Unknown source file.'}
                        $sequence++; $records+=,$r
                    }
                    'end' {
                        if ($state -ne 'observations' -or $r.observations -ne $sequence -or $r.status -cne 'body-finished-outcome-unverified') {throw 'Invalid end.'}
                        $state='done'
                    }
                    default {throw 'Unknown record.'}
                }
            } catch {$valid=$false; $counts.malformed++}
        }
        if ($state -ne 'done') {$counts.incomplete++; $valid=$false}
        if (-not $valid) {continue}
        foreach ($r in $records) {
            $counts.observations++
            if ($r.execution -cne $execution) {$counts.malformed++; continue}
            # Only source metadata is hashed, never observed directory values or credentials.
            $site=HashText ($testMethod + [char]0 + $r.sourceFile + [char]0 + $r.sourceMember + [char]0 + $r.sourceLine + [char]0 + $r.role + [char]0 + $r.origin)
            $left=Scalar $r.value
            if ($r.origin -ceq 'explicit-microsoft-comparison') {
                $right=Scalar $r.other
                if ($null -eq $left -or $null -eq $right) {$counts.redactedOrUnsupported++; continue}
                $counts.explicitPairs++
                $same=($left.type -ceq $right.type -and $left.value -ceq $right.value)
                [Console]::WriteLine((@{kind='reviewed-scalar-pair';framework=$Framework;commit=$source.commit;execution=$execution;testMethodSha256=(HashText $testMethod);sourceSiteSha256=$site;record=$counts.observations;microsoftExpectedObservation=$left;ourActualObservation=$right;observedScalarsEqual=$same;candidate=($(if ($same) {'matching-scalars'} else {'mismatching-scalars'}));theoryInputMapping='unresolved';assertionOutcome='unverified';replayEligibility='unverified'} | ConvertTo-Json -Depth 6 -Compress))
            } elseif ($r.origin -ceq 'assertion-operand-unverified') {
                $counts.unverifiedOperands++
                if ($null -eq $left) {$counts.redactedOrUnsupported++; continue}
                [Console]::WriteLine((@{kind='unverified-assertion-operand';framework=$Framework;commit=$source.commit;execution=$execution;testMethodSha256=(HashText $testMethod);sourceSiteSha256=$site;record=$counts.observations;operand=$left;theoryInputMapping='unresolved';microsoftOrigin='unverified';replayEligibility='unverified'} | ConvertTo-Json -Depth 6 -Compress))
            } else {$counts.malformed++}
        }
    }
    [Console]::WriteLine((@{kind='capture-summary';framework=$Framework;capturePolicy=$policy;commit=$source.commit;sourceTreeSha256=$review.sourceTreeSha256;assemblySha256=$review.assemblySha256;counts=$counts;coverage='partial-not-runtime-coverage';cleanup='unverified';rawFiles='private-runner-only'} | ConvertTo-Json -Depth 5 -Compress))
    if ($counts.files -eq 0 -or $counts.malformed -gt 0 -or $counts.incomplete -gt 0) {exit 1}
    exit 0
} catch {
    [Console]::WriteLine('Capture helper blocked or failed. No raw diagnostics exported; inspect private runner files.')
    exit 2
}
