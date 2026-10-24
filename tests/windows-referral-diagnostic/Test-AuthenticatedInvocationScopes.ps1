# Pure regression: execute the same preflight path as the one-off workflow,
# in fresh processes so script functions cannot leak between invocation scopes.
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$executable = (Get-Process -Id $PID).Path
$preflight = './tests/windows-referral-diagnostic/Test-AuthenticatedFixture.ps1'
$expected = 'Authenticated helper pure tests, syntax and token bridge compilation passed; no Windows operations executed.'
$wrapper = Join-Path ([IO.Path]::GetTempPath()) ("adfl-pure-scope-" + [Guid]::NewGuid().ToString('N') + '.ps1')
try {
    # GitHub writes the run block into a script, then invokes pwsh -command ". '{0}'".
    [IO.File]::WriteAllText($wrapper, "$preflight`n", [Text.UTF8Encoding]::new($false))
    Push-Location $repository
    try {
        foreach ($scope in @('direct-file', 'workflow-wrapper')) {
            $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive')
            if ($scope -eq 'direct-file') { $arguments += @('-File', $preflight) }
            else { $arguments += @('-Command', (". '" + $wrapper.Replace("'", "''") + "'")) }
            $output = @(& $executable @arguments 2>&1)
            $code = $LASTEXITCODE
            if ($code -ne 0) { throw "Pure preflight failed in $scope (exit $code): $($output -join [Environment]::NewLine)" }
            if (($output -join [Environment]::NewLine).Trim() -cne $expected) { throw "Unexpected pure preflight output in $scope." }
            Write-Host "PASS $scope using $preflight"
        }
    } finally { Pop-Location }
} finally {
    if (Test-Path -LiteralPath $wrapper) { Remove-Item -LiteralPath $wrapper -Force }
}
