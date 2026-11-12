#!/usr/bin/env python3
"""Partition the functional suite between guarded offline and authorized Samba processes."""
import argparse
import os
from pathlib import Path
import runpy
import subprocess
import sys

sys.dont_write_bytecode = True
offline = runpy.run_path(str(Path(__file__).with_name("run-offline-tests.py")))


def prepare(framework, environment=None):
    environment = dict(os.environ if environment is None else environment)
    if environment.get("ADFL_OFFLINE_TESTS"):
        raise ValueError("Refusing live execution from an offline-guarded parent; the guard is never removed.")
    if framework not in ("net8.0", "net10.0"):
        raise ValueError("Unsupported runtime.")
    project, defaults = offline["GROUPS"]["functional"]
    classes = list(dict.fromkeys(defaults + offline["EXTRA"].get("functional", [])))
    guarded, _ = offline["prepare"]("functional", framework, classes)
    # Exact complements of the same canonical set: every test is assigned to
    # one process. In particular ConnectionPoolSambaTests stays in the live set.
    remainder = "&".join(f"FullyQualifiedName!~{project}.{name}." for name in classes)
    live = ["dotnet", "test", f"tests/{project}/{project}.csproj", "--configuration", "Release",
            "--framework", framework, "--no-restore", "--filter", remainder]
    environment["DOTNET_GENERATE_ASPNET_CERTIFICATE"] = "false"
    return [(["dotnet", "restore", f"tests/{project}/{project}.csproj"], environment),
            (guarded, dict(environment, ADFL_OFFLINE_TESTS="1")), (live, environment)]


def run(framework):
    for command, environment in prepare(framework):
        result = subprocess.run(command, cwd=offline["ROOT"], env=environment, check=False)
        if result.returncode:
            return result.returncode
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-disposable-samba", action="store_true", required=True)
    parser.add_argument("--framework", choices=["net8.0", "net10.0"], required=True)
    args = parser.parse_args()
    try:
        return run(args.framework)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
