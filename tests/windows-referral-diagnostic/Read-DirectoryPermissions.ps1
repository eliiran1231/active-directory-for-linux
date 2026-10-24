# Read only: fixed existing directory candidates, no enumeration of children,
# access attempts as another identity, account APIs, writes, or ACL changes.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Authenticated-Integration.ps1')
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Disposable hosted Windows required.'
}
function Get-PrincipalCategory([string]$Sid, [string]$Runner) {
    if ($Sid -eq $Runner) { return 'runner' }
    switch ($Sid) {
        'S-1-5-18' { 'system'; break }
        'S-1-5-32-544' { 'administrators'; break }
        'S-1-5-32-545' { 'standard-users'; break }
        'S-1-5-11' { 'authenticated-users'; break }
        'S-1-1-0' { 'everyone'; break }
        'S-1-3-0' { 'creator-owner'; break }
        'S-1-3-1' { 'creator-group'; break }
        'S-1-3-4' { 'owner-rights'; break }
        default { 'other' }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $runner = $identity.User.Value
    # Labels only leave this process. Never print paths, names, raw SIDs or SDDL.
    $candidates = [ordered]@{
        'runner-temp' = $env:RUNNER_TEMP
        'process-temp' = $env:TEMP
        'runner-profile' = $env:USERPROFILE
        'local-appdata' = $env:LOCALAPPDATA
        'local-appdata-temp' = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Temp' } else { $null }
        'workspace' = $env:GITHUB_WORKSPACE
    }
    foreach ($label in $candidates.Keys) {
        try {
            $path = $candidates[$label]
            if (!$path -or !(Test-Path -LiteralPath $path -PathType Container)) {
                @{ Candidate = $label; Status = 'absent' } | ConvertTo-Json -Compress | Write-Host
                continue
            }
            $item = Get-Item -LiteralPath $path -Force
            $acl = Get-Acl -LiteralPath $path
            $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            if ($rules.Count -gt 64) { throw 'ACL output bound exceeded.' }
            $allowed = @($rules | Where-Object AccessControlType -EQ 'Allow' | ForEach-Object { $_.IdentityReference.Value })
            $permitted = @($runner, 'S-1-5-18', 'S-1-5-32-544')
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
            $rows = @(); $index = 0
            foreach ($rule in $rules) {
                $rows += @{
                    Index = $index++; Principal = Get-PrincipalCategory $rule.IdentityReference.Value $runner
                    Type = $rule.AccessControlType.ToString(); Rights = [long]$rule.FileSystemRights
                    Inherited = $rule.IsInherited
                    Inheritance = [int]$rule.InheritanceFlags; Propagation = [int]$rule.PropagationFlags
                    ApprovedPrincipal = ($rule.IdentityReference.Value -in $permitted)
                }
            }
            @{
                Candidate = $label; Status = 'read'; Owner = Get-PrincipalCategory $owner $runner
                OwnerApproved = ($owner -in $permitted); AllowCount = $allowed.Count
                UnapprovedAllowCount = @($allowed | Where-Object { $_ -notin $permitted }).Count
                CurrentGuardPass = (Test-DiagnosticPrivateAccess $owner $runner $allowed)
                DaclPresent = $descriptor.DiscretionaryAcl -ne $null
                Canonical = $acl.AreAccessRulesCanonical; InheritanceProtected = $acl.AreAccessRulesProtected
                ReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                Rules = $rows
            } | ConvertTo-Json -Depth 5 -Compress | Write-Host
        } catch {
            # No raw exception or path; inability to inspect is never interpreted as private.
            @{ Candidate = $label; Status = 'unavailable' } | ConvertTo-Json -Compress | Write-Host
        }
    }
} finally { $identity.Dispose() }
