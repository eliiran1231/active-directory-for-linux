# Definitions only. No entry point, workflow, Windows calls or trust changes.
# Adapters are injected so failure paths can be exercised without creating users.
function Assert-AuthenticatedManifest($State) {
    if (($State.Keys | Sort-Object) -join ',' -cne 'Accounts,Nonce,Version' -or
        $State.Version -ne 1 -or $State.Nonce -cnotmatch '^[0-9a-f]{32}$' -or $State.Accounts.Count -ne 2) {
        throw 'Invalid manifest schema.'
    }
    for ($index = 0; $index -lt 2; $index++) {
        $account = $State.Accounts[$index]
        $expected = 'adfl' + @('A', 'B')[$index] + $State.Nonce.Substring(0, 12)
        if (($account.Keys | Sort-Object) -join ',' -cne 'Name,Sid,State' -or
            $account.Name -cne $expected -or $account.State -notin @('planned', 'creating', 'owned')) { throw 'Invalid account manifest.' }
        if ($account.State -eq 'owned') {
            if ($account.Sid -isnot [string] -or $account.Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid owned SID.' }
        } elseif ($null -ne $account.Sid) { throw 'Unowned account has SID.' }
    }
    if ($State.Accounts[0].Sid -and $State.Accounts[0].Sid -eq $State.Accounts[1].Sid) { throw 'Duplicate account SID.' }
}

function Read-AuthenticatedManifest([string]$Path) {
    $state = Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json -AsHashtable
    Assert-AuthenticatedManifest $state
    return $state
}

function Save-AuthenticatedManifest($State, [string]$Path) {
    Assert-AuthenticatedManifest $State # Reject secret-bearing or unexpected fields.
    $bytes = [Text.Encoding]::UTF8.GetBytes(($State | ConvertTo-Json -Depth 8))
    $temporary = "$Path.new"
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    [IO.File]::Move($temporary, $Path, $true)
}

function New-AuthenticatedManifest {
    $nonce = [Guid]::NewGuid().ToString('N')
    return @{ Version = 1; Nonce = $nonce; Accounts = @(
        @{ Name = "adflA$($nonce.Substring(0, 12))"; Sid = $null; State = 'planned' },
        @{ Name = "adflB$($nonce.Substring(0, 12))"; Sid = $null; State = 'planned' }
    ) }
}

function Initialize-AuthenticatedAccounts($State, [scriptblock]$Save, $Operations) {
    Assert-AuthenticatedManifest $State
    if ($State.Accounts.Count -ne 2 -or $State.Accounts[0].Name -eq $State.Accounts[1].Name) { throw 'Two distinct accounts required.' }
    # Preflight both names before any creation. Existing names never become owned.
    foreach ($account in $State.Accounts) {
        if ($account.State -ne 'planned' -or $account.Sid) { throw 'Setup cannot resume or rerun.' }
        if (& $Operations.Exists $account.Name) { throw 'Account name already exists; no creation permitted.' }
    }
    & $Save
    foreach ($account in $State.Accounts) {
        $account.State = 'creating'
        & $Save # Durable intent precedes mutation; not sufficient authority to delete.
        $sid = & $Operations.Create $account.Name
        if ($sid -isnot [string] -or $sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Created account SID unavailable; ownership unresolved.' }
        $account.Sid = $sid
        $account.State = 'owned'
        & $Save # No next account or test until SID ownership is durably recorded.
        if ($Operations.ContainsKey('PrepareStandardUser')) { & $Operations.PrepareStandardUser $sid }
    }
}

function Remove-AuthenticatedObjects($State, $Operations) {
    # Stop/verify the owned worker first. If that fails, do not race live mutation.
    & $Operations.StopWorker
    $failures = [Collections.Generic.List[string]]::new()
    $accounts = @()
    try { Assert-AuthenticatedManifest $State; $accounts = $State.Accounts }
    catch { $failures.Add('account-manifest') }
    foreach ($account in $accounts) {
        try {
            if ($account.State -eq 'planned') { continue }
            if (!$account.Sid -or $account.State -ne 'owned') { throw 'Unresolved account ownership.' }
            $currentSid = & $Operations.FindSid $account.Name
            if ($null -eq $currentSid) { continue }
            if ($currentSid -cne $account.Sid) { throw 'Account SID mismatch.' }
            & $Operations.RemoveAccount $account.Sid
            if ($null -ne (& $Operations.FindSid $account.Name)) { throw 'Account absence not verified.' }
        } catch { $failures.Add("account:$($account.Name)") }
    }
    # Each callback must enforce its own exact manifest ownership and verify absence.
    foreach ($kind in @('Certificate', 'ProviderKey', 'Pfx')) {
        try { if ($Operations.ContainsKey($kind)) { & $Operations[$kind] } } catch { $failures.Add($kind) }
    }
    return ,$failures.ToArray() # Sanitized identifiers only; never exception messages.
}

function Invoke-AuthenticatedStages([scriptblock]$Run) {
    $results = [ordered]@{}
    foreach ($identity in @('original', 'a', 'b')) {
        foreach ($stage in @('direct', 'referral', 'retained-primary')) {
            $name = "$identity-$stage"
            $allowed = $stage -eq 'direct' -or
                ($stage -eq 'referral' -and $results["$identity-direct"] -eq 'passed') -or
                ($stage -eq 'retained-primary' -and $results["$identity-referral"] -eq 'passed')
            if (!$allowed) { $results[$name] = 'skipped'; continue }
            try {
                $passed = & $Run $name
                if ($passed -isnot [bool]) { throw 'Invalid native stage result.' }
                $results[$name] = if ($passed) { 'passed' } else { 'failed' }
            } catch { $results[$name] = 'failed' }
        }
    }
    foreach ($name in @('a-to-b', 'b-to-a')) {
        if ($results['a-retained-primary'] -ne 'passed' -or $results['b-retained-primary'] -ne 'passed') {
            $results[$name] = 'skipped'; continue
        }
        try {
            $passed = & $Run $name
            if ($passed -isnot [bool]) { throw 'Invalid native stage result.' }
            $results[$name] = if ($passed) { 'passed' } else { 'failed' }
        } catch { $results[$name] = 'failed' }
    }
    return $results
}
