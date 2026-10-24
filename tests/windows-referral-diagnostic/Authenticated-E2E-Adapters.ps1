# Definitions only. These adapters never call account/token/certificate-store APIs.
# The fixture loads this file instead of the real adapters in explicit E2E modes.
function Read-E2EAccounts {
    $path = Join-Path $root 'e2e-accounts.json'
    if (!(Test-Path -LiteralPath $path)) { return @{} }
    return (Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable)
}
function New-E2EAccountOperations {
    return @{
        Exists = { param($name) (Read-E2EAccounts).ContainsKey($name) }
        Create = {
            param($name)
            $fake = Read-E2EAccounts
            if ($E2ECase -eq 'SecondCreateFailure' -and $fake.Count -eq 1) {
                $record = Read-AuthenticatedManifest $accountPath
                if ($record.Accounts[0].State -ne 'owned' -or !$record.Accounts[0].Sid -or $record.Accounts[1].State -ne 'creating') { throw 'First fake ownership not durable.' }
                [IO.File]::WriteAllText((Join-Path $root 'e2e-fault.txt'), $E2ECase)
                throw 'Injected second fake creation failure.'
            }
            $sid = 'S-1-5-21-1-2-3-' + (1001 + $fake.Count)
            $fake[$name] = $sid
            Save-DiagnosticJson $fake (Join-Path $root 'e2e-accounts.json')
            return $sid
        }
        PrepareStandardUser = { param($sid) } # No group membership operations.
        FindSid = { param($name) $fake = Read-E2EAccounts; if ($fake.ContainsKey($name)) { return $fake[$name] } }
        RemoveAccount = {
            param($sid)
            $fake = Read-E2EAccounts
            $marker = Join-Path $root 'e2e-account-cleanup-fault.txt'
            if ($E2ECase -eq 'CleanupFailures' -and !(Test-Path -LiteralPath $marker)) {
                [IO.File]::WriteAllText($marker, 'injected once')
                [IO.File]::WriteAllText((Join-Path $root 'e2e-fault.txt'), $E2ECase)
                throw 'Injected fake removal failure.'
            }
            foreach ($name in @($fake.Keys)) { if ($fake[$name] -ceq $sid) { $fake.Remove($name) } }
            Save-DiagnosticJson $fake (Join-Path $root 'e2e-accounts.json')
        }
    }
}
function New-E2EToken([int]$Index, $Transfer = $null) {
    if ($null -eq $Transfer) { $Transfer = [AdflE2ETransfer]::new() }
    $value = [pscustomobject]@{ Index = $Index; Root = $root; Case = $E2ECase; Disposed = $false; Transfer = $Transfer }
    $value | Add-Member ScriptMethod CopyTo {
        param($process)
        if ($this.Disposed) { throw 'Fake token already disposed.' }
        if ($this.Case -eq 'PartialHandoff' -and $this.Index -eq 2) {
            [IO.File]::WriteAllText([IO.Path]::Combine($this.Root, 'e2e-fault.txt'), $this.Case)
            throw 'Injected second fake copy failure.'
        }
        $copy = $this.Transfer.CopyTo($process)
        $path = [IO.Path]::Combine($this.Root, "e2e-copy-$($this.Index).txt")
        $count = if ([IO.File]::Exists($path)) { [int][IO.File]::ReadAllText($path) } else { 0 }
        [IO.File]::WriteAllText($path, ($count + 1).ToString())
        return [long]$copy # A harmless event handle in hosted E2E, never a token handle.
    }
    $value | Add-Member ScriptMethod Dispose {
        $this.Disposed = $true
        $this.Transfer.Dispose()
        [IO.File]::WriteAllText([IO.Path]::Combine($this.Root, "e2e-token-$($this.Index)-disposed.txt"), 'disposed')
    }
    return $value
}
function New-E2ECertificate {
    Stage 'certificate-generate'
    Stage 'certificate-export'
    Save-DiagnosticJson @{ Version = 1; RunId = $RunId; TestOnly = $true } $certificatePath
    Stage 'pfx-write'
    [IO.File]::WriteAllText($pfxPath, 'DUMMY NON-SECRET PAYLOAD; NOT A CERTIFICATE OR KEY')
    Assert-DiagnosticDirectoryPrivate $pfxPath # Real inherited file ACL, no cryptographic object.
    Stage 'certificate-import' # Fake marker only, never a store operation.
    [IO.File]::WriteAllText((Join-Path $root 'e2e-certificate.txt'), 'fake trust marker')
    if ($E2ECase -eq 'SetupTimeout') {
        [IO.File]::WriteAllText((Join-Path $root 'e2e-fault.txt'), $E2ECase)
        Start-Sleep -Seconds 120
    }
    Stage 'certificate-verify'
    if ([IO.File]::ReadAllText($pfxPath) -cne 'DUMMY NON-SECRET PAYLOAD; NOT A CERTIFICATE OR KEY') { throw 'Dummy file round trip failed.' }
    Stage 'managed-chain'
    return ('A' * 40)
}
function Remove-E2ECertificate {
    if (!(Test-Path -LiteralPath $certificatePath)) { return }
    $record = Get-Content -Raw -LiteralPath $certificatePath | ConvertFrom-Json -AsHashtable
    if ($record.Version -ne 1 -or $record.RunId -cne $RunId -or $record.TestOnly -isnot [bool] -or !$record.TestOnly) {
        throw 'Fake certificate ownership mismatch.'
    }
    $fault = Join-Path $root 'e2e-certificate-cleanup-fault.txt'
    if ($E2ECase -eq 'CleanupFailures' -and !(Test-Path -LiteralPath $fault)) {
        [IO.File]::WriteAllText($fault, 'injected once'); throw 'Injected fake certificate cleanup failure.'
    }
    $marker = Join-Path $root 'e2e-certificate.txt'
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker }
    if (Test-Path -LiteralPath $marker) { throw 'Fake certificate remains.' }
}
