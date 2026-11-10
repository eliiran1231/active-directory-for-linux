#!/usr/bin/env python3
"""Run only the four linked, detached differential classes against recordings."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from extract import ROOT, SOURCES, CASE_COUNT, case_names, sha

HERE = Path(__file__).resolve().parent


def verify():
    manifest = json.loads((HERE / "results/manifest.json").read_text())
    if manifest["schemaVersion"] != 1:
        raise ValueError("Unsupported manifest schema")
    if [row["path"] for row in manifest["caseSources"]] != SOURCES:
        raise ValueError("Unexpected linked source scope")
    for source in manifest["caseSources"]:
        if sha((ROOT / source["path"]).read_bytes()) != source["replaySourceSha256"]:
            raise ValueError("Linked case source changed; review and refresh provenance before replay")
    expected_fixtures = {f"run202-{framework}.json" for framework in ("net8.0", "net10.0")}
    if {row["path"] for row in manifest["fixtures"]} != expected_fixtures or len(manifest["fixtures"]) != 2:
        raise ValueError("Unexpected fixture scope")
    for row in manifest["fixtures"]:
        raw = (HERE / "results" / row["path"]).read_bytes()
        if sha(raw) != row["sha256"]:
            raise ValueError("Recording hash mismatch")
        fixture = json.loads(raw)
        if fixture["schemaVersion"] != 1 or set(fixture["cases"]) != case_names() or row["caseCount"] != CASE_COUNT:
            raise ValueError("Missing, extra or invalid recorded case")
        for case in fixture["cases"].values():
            if case["policy"] != "match-microsoft" or case["sourceOutcome"] != "Passed" or not case["microsoft"]:
                raise ValueError("Unsupported recording policy or observation")


def prepare(framework, dotnet="dotnet", results_directory=None):
    if framework not in ("net8.0", "net10.0"):
        raise ValueError("Unsupported runtime")
    verify()
    command = [dotnet, "test", str(HERE / "AdForLinux.DifferentialTests.csproj"),
               "--configuration", "Release", "--framework", framework, "--no-restore"]
    if results_directory:
        command += ["--logger", f"trx;LogFileName=differential-replay-{framework}.trx",
                    "--results-directory", str(Path(results_directory).resolve())]
    environment = os.environ.copy()
    environment["ADFL_OFFLINE_TESTS"] = "1"
    return command, environment


def verify_execution(path):
    ns = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
    rows = ET.parse(path).findall(".//t:UnitTestResult", ns)
    if len(rows) != CASE_COUNT or {row.get("testName") for row in rows} != case_names():
        raise ValueError(f"Replay must execute exactly all {CASE_COUNT} recorded cases")
    if any(row.get("outcome") != "Passed" for row in rows):
        raise ValueError("Replay has a non-passing case")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", required=True, choices=("net8.0", "net10.0"))
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--results-directory")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    results_parent = Path(args.results_directory).resolve() if args.results_directory else ROOT / "TestResults/differential-replay"
    if args.check_only:
        command, environment = prepare(args.framework, args.dotnet, results_parent)
        print(json.dumps({"command": command, "offline_mode": environment["ADFL_OFFLINE_TESTS"], "recorded_cases": CASE_COUNT}))
        return 0
    # A fresh directory prevents an old successful TRX from satisfying coverage.
    results_parent.mkdir(parents=True, exist_ok=True)
    results_directory = Path(tempfile.mkdtemp(prefix=args.framework + "-", dir=results_parent))
    command, environment = prepare(args.framework, args.dotnet, results_directory)
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    if result.returncode:
        return result.returncode
    verify_execution(results_directory / f"differential-replay-{args.framework}.trx")
    print(f"Verified {CASE_COUNT} passing recorded cases. Results: {results_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
