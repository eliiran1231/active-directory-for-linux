#!/usr/bin/env python3
"""Four guarded self-termination drills; no admission, credentials or LDAP."""
import argparse
import os
from pathlib import Path
import signal
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--dotnet", required=True)
options = parser.parse_args()
root = Path(__file__).resolve().parent
environment = {key: os.environ[key] for key in ("PATH", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO", "XDG_RUNTIME_DIR",
    "TMPDIR", "TMP", "TEMP", "SystemRoot", "WINDIR") if key in os.environ}
environment.update(ADFL_OFFLINE_TESTS="1", DOTNET_EnableDiagnostics="0", COMPlus_EnableDiagnostics="0",
    DOTNET_DbgEnableMiniDump="0", COMPlus_DbgEnableMiniDump="0")
count = 0
for framework in ("net8.0", "net10.0"):
    assembly = root / "bin" / "Release" / framework / "AccountManagement.ReadProbe.dll"
    harness = root / "termination-check" / "bin" / "Release" / framework / "TerminationCheck.dll"
    if not assembly.is_file() or not harness.is_file(): raise SystemExit("BLOCKED missing built termination harness")
    for mode in ("exit-handler", "stderr"):
        result = subprocess.run([options.dotnet, str(harness), str(assembly), mode], env=environment,
            input="", capture_output=True, text=True, timeout=5, check=False)
        if result.stdout or result.stderr or (result.returncode != -signal.SIGKILL if os.name != "nt" else result.returncode in (0, 2)):
            raise SystemExit("FAIL guarded termination " + framework + "/" + mode)
        count += 1
print(f"PASS {count} guarded self-termination drills; no LDAP or credential input")
