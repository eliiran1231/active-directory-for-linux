# Definitions only. Not dot-sourced by any workflow. No execution on import.
function New-AuthenticatedWindowsAccountOperations($Credentials) {
    if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
        throw 'Disposable GitHub-hosted Windows only.'
    }
    return @{
        Exists = { param($name) $null -ne (Get-LocalUser -ErrorAction Stop | Where-Object Name -IEQ $name) }
        Create = {
            param($name)
            $secret = [Security.SecureString]::new()
            $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
            try {
                # Guaranteed mixed classes, then 48 independent random characters.
                foreach ($c in 'aA9!'.ToCharArray()) { $secret.AppendChar($c) }
                foreach ($b in $bytes) { $secret.AppendChar([char](33 + ($b % 94))) }
                $secret.MakeReadOnly()
                $Credentials.Add($name, $secret)
                $user = New-LocalUser -Name $name -Password $secret -Description 'ADFL disposable diagnostic' -ErrorAction Stop
                return $user.SID.Value
            } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        }.GetNewClosure()
        PrepareStandardUser = {
            param($sid)
            # Standard Users only, SID avoids localization. No privileges/logon rights.
            $group = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
            $existing = Get-LocalGroupMember -SID $group -ErrorAction Stop | Where-Object { $_.SID.Value -eq $sid }
            if (!$existing) { Add-LocalGroupMember -SID $group -Member $sid -ErrorAction Stop }
        }
        FindSid = {
            param($name)
            $user = Get-LocalUser -ErrorAction Stop | Where-Object Name -IEQ $name
            if ($null -ne $user) { return $user.SID.Value }
        }
        RemoveAccount = {
            param($sid)
            Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($sid)) -ErrorAction Stop
        }
    }
}

function Clear-AuthenticatedCredentials($Credentials) {
    foreach ($secret in $Credentials.Values) { $secret.Dispose() }
    $Credentials.Clear()
}

function Stop-AuthenticatedWorker($Record) {
    if ($null -eq $Record) { return }
    $worker = $null
    try { $worker = [Diagnostics.Process]::GetProcessById([int]$Record.ProcessId) }
    catch [ArgumentException] { return }
    try {
        if ($worker.StartTime.ToUniversalTime().Ticks.ToString() -cne [string]$Record.StartTicks) {
            throw 'Worker identity mismatch; do not terminate an unrelated process.'
        }
        if (!$worker.HasExited) {
            $worker.Kill($true)
            if (!$worker.WaitForExit(10000)) { throw 'Worker exit not confirmed.' }
        }
    } catch [InvalidOperationException], [ComponentModel.Win32Exception] {
        if (!$worker.HasExited) { throw } # Only a confirmed exit can excuse a StartTime/Kill race.
    } finally { if ($worker) { $worker.Dispose() } }
}
