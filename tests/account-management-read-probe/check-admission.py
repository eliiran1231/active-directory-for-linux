#!/usr/bin/env python3
"""Nonsecret admission refusals only: sealed empty stdin, no live read execution."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--dotnet", required=True)
options = parser.parse_args()
if os.environ.get("ADFL_OFFLINE_TESTS"):
    raise SystemExit("BLOCKED inherited offline guard; use check-blocked.py without removing the guard")
environment = {key: os.environ[key] for key in (
    "PATH", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP", "SystemRoot", "WINDIR",
) if key in os.environ}
environment.update(ADFL_ACCOUNT_READ_PROBE="1", LDAPTLS_REQCERT="demand", LDAPTLS_REQSAN="demand",
                   DOTNET_EnableDiagnostics="0", COMPlus_EnableDiagnostics="0", DOTNET_DbgEnableMiniDump="0", COMPlus_DbgEnableMiniDump="0")
arguments = ["--supervised-read", "--allow-live-read", "--host", "offline.invalid", "--port", "636",
             "--fixture-dn", "CN=synthetic,DC=example,DC=test", "--schema-dn", "CN=Schema,CN=Configuration,DC=example,DC=test",
             "--sam", "synthetic", "--guid", "3530d727-e62c-45ea-8cc0-a110d8482981"]
cases = [
    ("cli", [], {}, "missing-cli-opt-in"),
    ("environment", arguments, {"ADFL_ACCOUNT_READ_PROBE": "0"}, "missing-environment-opt-in"),
    ("supervisor", arguments[1:], {}, "supervisor-required"),
    ("unknown", arguments + ["--password", "synthetic"], {}, "invalid-explicit-configuration"),
    ("duplicate", arguments + ["--host", "other.invalid"], {}, "invalid-explicit-configuration"),
    ("duplicate-opt-in", arguments + ["--allow-live-read"], {}, "invalid-explicit-configuration"),
    ("missing-value", arguments[:-1], {}, "invalid-explicit-configuration"),
    ("zero-guid", arguments[:-1] + ["00000000-0000-0000-0000-000000000000"], {}, "invalid-explicit-configuration"),
    ("valid-blocked", arguments, {}, "containment-review-pending"),
]
if os.name != "nt":
    cases += [("tls", arguments, {"LDAPTLS_REQCERT": "never"}, "strict-native-tls-policy-required"),
              ("san", arguments, {"LDAPTLS_REQSAN": "allow"}, "strict-native-tls-policy-required")]
count = 0
for framework in ("net8.0", "net10.0"):
    assembly = Path(__file__).resolve().parent / "bin" / "Release" / framework / "AccountManagement.ReadProbe.dll"
    if not assembly.is_file(): raise SystemExit("BLOCKED missing built probe")
    for label, flags, overrides, expected in cases:
        # Empty redirected stdin makes credential acquisition impossible even
        # if a regression emits READY. No credential variables are inspected.
        result = subprocess.run([options.dotnet, str(assembly), *flags], env=dict(environment, **overrides),
                                input="", capture_output=True, text=True, timeout=10, check=False)
        if result.returncode != 2 or result.stdout or result.stderr.strip() != "BLOCKED " + expected:
            raise SystemExit("FAIL nonsecret admission " + framework + "/" + label)
        count += 1
print(f"PASS {count} nonsecret admission refusals; no AD integration run")
