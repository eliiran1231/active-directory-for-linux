#!/usr/bin/env python3
"""Extract only explicit Microsoft observations from the retained run #202 TRX."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
import zipfile
import structured

ROOT = Path(__file__).resolve().parents[3]
BASE = "36d9bc3a6d92e0909a55ec44a646e1e56a30443f"
RUN = "https://github.com/eliiran1231/active-directory-for-linux/actions/runs/42872964497"
PREFIX = "AdForLinux.DifferentialTests."
PRINCIPAL = "PrincipalValueCollectionTraversalAndCopyComparisonTests"
RESULT = "ResultValueEnumeratorComparisonTests"
COPY_FAILURE = "PrincipalValueCollectionCopyFailureComparisonTests"
GROUP_CONSTRUCTOR = "GroupConstructorValidationComparisonTests"
CLASSES = (PRINCIPAL, RESULT, COPY_FAILURE, GROUP_CONSTRUCTOR)
CASE_COUNT = 42
SOURCES = [f"tests/windows/AdForLinux.DifferentialTests/{name}.cs" for name in CLASSES]


def case_names():
    result = set()
    for mutation, flag in itertools.product(("clear", "remove-current", "append-after-end", "append-while-positioned"), (False, True)):
        result.add(f'{PREFIX}{PRINCIPAL}.Current_after_count_changes_matches_microsoft(mutation: "{mutation}", nonGeneric: {flag})')
    for index, flag in itertools.product((4, 2, 3, -1, 1), (False, True)):
        result.add(f'{PREFIX}{PRINCIPAL}.Copy_destination_bounds_match_microsoft(index: {index}, generic: {flag})')
    for method, flag, position in itertools.product(("Current_position_validation_matches", "Reset_restarts_traversal_like_microsoft"), (False, True), ("before", "positioned", "finished")):
        result.add(f'{PREFIX}{RESULT}.{method}(throughInterface: {flag}, position: "{position}")')
    for generic, compatible in itertools.product((False, True), repeat=2):
        result.add(f'{PREFIX}{COPY_FAILURE}.Copy_to_covariant_array_matches_failure_and_partial_writes(generic: {generic}, compatible: {compatible})')
    for empty in (False, True):
        result.add(f'{PREFIX}{COPY_FAILURE}.Non_generic_copy_to_incompatible_element_type_matches_microsoft(empty: {empty})')
    for count in (0, 1):
        result.add(f'{PREFIX}{COPY_FAILURE}.Non_generic_copy_to_multidimensional_array_matches_validation(count: {count})')
    for named, name in ((False, None), (True, None), (True, ""), (True, "group-name")):
        argument = "null" if name is None else json.dumps(name)
        result.add(f'{PREFIX}{GROUP_CONSTRUCTOR}.Null_context_matches_microsoft_for_each_constructor(named: {named}, name: {argument})')
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def extract_member(data, framework):
    root = ET.fromstring(data)
    ns = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
    expected = case_names()
    observations = {}
    headers = set()
    for result in root.findall(".//t:UnitTestResult", ns):
        name = result.get("testName", "")
        stdout = result.findtext("t:Output/t:StdOut", default="", namespaces=ns)
        # TRX emitted literal escaped CRLFs in this artifact. Accept real CRLFs too.
        lines = stdout.replace("\\r\\n", "\n").splitlines()
        if name.startswith(PREFIX + "FixtureRegistrationTests.") and lines:
            headers.add(tuple(lines))
        if name not in expected:
            if any(name.startswith(PREFIX + selected + ".") for selected in CLASSES):
                raise ValueError(f"Unexpected source case in selected class: {name}")
            continue
        if name in observations:
            raise ValueError(f"Duplicate recorded case: {name}")
        if result.get("outcome") != "Passed":
            raise ValueError(f"Non-passing source case: {name}")
        marker = "System.DirectoryServices.AccountManagement: " if PRINCIPAL in name else "Microsoft: "
        recorded = [line[len(marker):] for line in lines if line.startswith(marker)]
        if len(recorded) != 1 or not recorded[0]:
            raise ValueError(f"Missing or ambiguous Microsoft observation: {name}")
        # This legacy constructor test prints both sides on one line. Its
        # exception observation has a fixed delimiter; never use the clone side.
        if GROUP_CONSTRUCTOR in name:
            if recorded[0].count("; AdForLinux: ") != 1:
                raise ValueError(f"Ambiguous legacy paired observation: {name}")
            recorded[0] = recorded[0].split("; AdForLinux: ", 1)[0]
        structured_row = structured.read(stdout, name, framework, BASE)
        if structured_row is not None and structured_row["microsoft"] != recorded[0]:
            raise ValueError(f"Structured and legacy Microsoft observations disagree: {name}")
        observations[name] = {"microsoft": recorded[0], "policy": "match-microsoft", "sourceOutcome": "Passed"}
    if set(observations) != expected:
        raise ValueError(f"Incomplete recording: missing {sorted(expected - set(observations))}")
    if len(headers) != 1:
        raise ValueError("Missing or inconsistent Windows provenance headers")
    header = dict(line.split(": ", 1) for line in headers.pop())
    if header.get("Commit/build") != BASE or not header.get("OS", "").startswith("Microsoft Windows "):
        raise ValueError("Wrong source commit or platform")
    target = "v8.0" if framework == "net8.0" else "v10.0"
    if not header.get("Runtime", "").endswith("Version=" + target):
        raise ValueError("Wrong source target framework")
    for package in ("Microsoft DirectoryServices", "Microsoft AccountManagement"):
        if not header.get(package, "").startswith("9.0.0+"):
            raise ValueError("Wrong Microsoft package version")
    return {"schemaVersion": 1, "framework": framework, "provenance": header,
            "cases": dict(sorted(observations.items()))}


def build(archive):
    archive_bytes = Path(archive).read_bytes()
    artifacts = {}
    sources = []
    for source in SOURCES:
        original = subprocess.check_output(["git", "show", f"{BASE}:{source}"], cwd=ROOT)
        sources.append({"path": source, "recordedSourceSha256": sha(original),
                        "replaySourceSha256": sha((ROOT / source).read_bytes())})
    with zipfile.ZipFile(archive) as z:
        for framework, suffix in (("net8.0", "net8"), ("net10.0", "net10")):
            member = f"tests/AdForLinux.DifferentialTests/TestResults/differential-{suffix}.trx"
            if z.namelist().count(member) != 1:
                raise ValueError(f"Missing or duplicate archive member: {member}")
            raw = z.read(member)
            fixture = extract_member(raw, framework)
            fixture["source"] = {"archiveMember": member, "sha256": sha(raw)}
            artifacts[f"run202-{framework}.json"] = encode(fixture)
    manifest = {"schemaVersion": 1, "sourceRun": RUN, "sourceCommit": BASE,
                "sourceArtifact": RUN + "/artifacts/13790049557",
                "sourceArchive": {"name": "results.zip", "sha256": sha(archive_bytes)},
                "caseSources": sources,
                "fixtures": [{"path": name, "sha256": sha(data), "caseCount": CASE_COUNT}
                             for name, data in sorted(artifacts.items())]}
    artifacts["manifest.json"] = encode(manifest)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--check", action="store_true", help="Verify byte-for-byte reproducibility; do not write")
    args = parser.parse_args()
    artifacts = build(args.archive)
    destination = Path(__file__).with_name("results")
    if args.check:
        for name, data in artifacts.items():
            if (destination / name).read_bytes() != data:
                raise ValueError(f"Non-reproducible fixture: {name}")
        print(f"Verified {2 * CASE_COUNT} Microsoft observations and provenance, byte for byte.")
    else:
        destination.mkdir(exist_ok=True)
        for name, data in artifacts.items():
            (destination / name).write_bytes(data)


if __name__ == "__main__":
    main()
