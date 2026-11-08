#!/usr/bin/env python3
"""Exercise only the probe's offline refusal, with no credential lookup."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--dotnet", required=True)
options = parser.parse_args()
directory = Path(__file__).resolve().parent
checks = 0
for framework in ("net8.0", "net10.0"):
    assembly = directory / "bin" / "Release" / framework / "AccountManagement.ReadProbe.dll"
    if not assembly.is_file():
        raise SystemExit(f"BLOCKED missing built {framework} probe; build both frameworks first")
    for guard in ("1", "0", "false"):
        # Carry only runtime settings; do not enumerate/copy credential-bearing
        # environment variables from the parent process.
        environment = {name: os.environ[name] for name in (
            "PATH", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO", "XDG_RUNTIME_DIR",
            "TMPDIR", "TMP", "TEMP", "LD_LIBRARY_PATH", "LANG", "LC_ALL",
        ) if name in os.environ}
        environment["ADFL_OFFLINE_TESTS"] = guard
        environment["ADFL_ACCOUNT_READ_PROBE"] = "1"
        # Never fetch credential values. Even a fully opted-in CLI is refused
        # at the first guard, before explicit configuration or secret access.
        arguments = [] if guard == "1" else [
            "--allow-live-read", "--host", "offline.invalid", "--port", "636",
            "--fixture-dn", "CN=synthetic,DC=example,DC=test", "--sam", "synthetic",
            "--guid", "3530d727-e62c-45ea-8cc0-a110d8482981",
        ]
        completed = subprocess.run([options.dotnet, str(assembly), *arguments],
            env=environment, capture_output=True, text=True, timeout=10, check=False)
        if completed.returncode != 2 or completed.stdout or completed.stderr.strip() != "BLOCKED offline-guard":
            raise SystemExit(f"FAIL {framework} guard={guard!r}: unexpected admission result")
        checks += 1
print(f"PASS {checks} guarded invocations blocked before credential access")
