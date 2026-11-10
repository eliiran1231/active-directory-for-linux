#!/usr/bin/env python3
"""Validate private suite captures; report coverage, never create an oracle fixture.

A matching source manifest + separately verified Windows execution are required
before interpreting values. This tool cannot attest a directory is synthetic or
that the Microsoft/clone test passed. It deliberately refuses incomplete runs.
"""
import argparse
import collections
import json
import pathlib
import re


def exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError("missing or unexpected capture fields")


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result



NUMERIC_MANIFEST = json.loads((pathlib.Path(__file__).with_name("numeric-sites.json")).read_text())
NUMERIC_SITES = {(site["testMethod"], site["sourceFile"], site["sourceLine"])
                 for site in NUMERIC_MANIFEST["sites"]}


def load(path):
    records = [json.loads(line, object_pairs_hook=unique_object)
               for line in path.read_text(encoding="utf-8").splitlines()]
    if len(records) < 2:
        raise ValueError("incomplete capture")
    begin, end = records[0], records[-1]
    exact_fields(begin, "kind schemaVersion execution testMethod source provenance")
    exact_fields(end, "kind schemaVersion execution observations status")
    if begin["kind"] != "begin" or end["kind"] != "end":
        raise ValueError("incomplete capture")
    execution = begin["execution"]
    if not matches(r"[0-9a-f]{32}", execution):
        raise ValueError("invalid execution identity")
    for record in records:
        if not isinstance(record, dict) or type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1 or record.get("execution") != execution:
            raise ValueError("mismatched schema/execution")
    if begin["source"] != "existing-windows-differential-suite":
        raise ValueError("invalid source")
    if not matches(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", begin["testMethod"]):
        raise ValueError("invalid test identity")
    provenance = begin["provenance"]
    exact_fields(provenance, "os architecture runtime target sdk commit assemblySha256 microsoftDirectoryServices microsoftAccountManagement offlineGuard capturePolicy")
    if provenance["capturePolicy"] != "redacted-scalars-v2":
        raise ValueError("unreviewed policy")
    if not matches(r"Microsoft Windows [0-9]+(?:\.[0-9]+){1,3}", provenance["os"]):
        raise ValueError("Microsoft observations require Windows provenance")
    if provenance["architecture"] not in ("X64", "X86", "Arm", "Arm64"):
        raise ValueError("unsupported architecture provenance")
    if not matches(r"\.NET (?:8|10)\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", provenance["runtime"]):
        raise ValueError("unsupported runtime provenance")
    if provenance["sdk"] is not None and not matches(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", provenance["sdk"]):
        raise ValueError("invalid SDK provenance")
    if provenance["commit"] is not None and not matches(r"[0-9a-f]{40}", provenance["commit"]):
        raise ValueError("invalid source commit provenance")
    if type(provenance["offlineGuard"]) is not bool:
        raise ValueError("invalid guard provenance")
    if provenance["target"] not in (".NETCoreApp,Version=v8.0", ".NETCoreApp,Version=v10.0"):
        raise ValueError("unsupported target provenance")
    if any(provenance[key] != "9.0.0.0" for key in ("microsoftDirectoryServices", "microsoftAccountManagement")):
        raise ValueError("unexpected Microsoft assembly provenance")
    if not matches(r"[0-9a-f]{64}", provenance["assemblySha256"]):
        raise ValueError("missing assembly hash")
    observations = records[1:-1]
    if type(end["observations"]) is not int or end["observations"] != len(observations):
        raise ValueError("inconsistent observation count")
    if end["status"] != "body-finished-outcome-unverified":
        raise ValueError("unrecognized completion marker")
    for index, row in enumerate(observations, 1):
        exact_fields(row, "kind schemaVersion execution sequence sourceFile sourceMember sourceLine role origin value other")
        if row["kind"] != "observation" or type(row["sequence"]) is not int or row["sequence"] != index:
            raise ValueError("out-of-order observation")
        if not matches(r"[A-Za-z_][A-Za-z0-9_.]*\.cs", row["sourceFile"]) or not matches(r"[A-Za-z_]\w*", row["sourceMember"]):
            raise ValueError("invalid source location")
        if type(row["sourceLine"]) is not int or not 1 <= row["sourceLine"] <= 2147483647:
            raise ValueError("invalid source line")
        if row["origin"] == "explicit-microsoft-comparison":
            if row["role"] not in ("value", "ordinal-ignore-case-set") or row["other"] is None:
                raise ValueError("invalid Microsoft comparison metadata")
            validate_snapshot(row["other"], (begin["testMethod"], row["sourceFile"], row["sourceLine"]) in NUMERIC_SITES)
        elif row["origin"] == "assertion-operand-unverified":
            if row["role"] not in ("assert-equal-expected", "assert-equal-actual") or row["other"] is not None:
                raise ValueError("invalid assertion operand metadata")
        else:
            raise ValueError("unknown origin")
        validate_snapshot(row["value"], (begin["testMethod"], row["sourceFile"], row["sourceLine"]) in NUMERIC_SITES)
    return begin, observations


BOUNDS = {"uint8": (0, 2**8 - 1), "int8": (-2**7, 2**7 - 1),
          "int16": (-2**15, 2**15 - 1), "uint16": (0, 2**16 - 1),
          "int32": (-2**31, 2**31 - 1), "uint32": (0, 2**32 - 1),
          "int64": (-2**63, 2**63 - 1), "uint64": (0, 2**64 - 1),
          "enum-int64": (-2**63, 2**63 - 1), "enum-uint64": (0, 2**64 - 1)}


def validate_snapshot(snapshot, allow_numeric=False):
    exact_fields(snapshot, "type value replayable")
    kind, value = snapshot["type"], snapshot["value"]
    if not isinstance(kind, str):
        raise ValueError("invalid snapshot type")
    if kind == "redacted":
        valid = value is None and snapshot["replayable"] is False
    elif kind == "null":
        valid = value is None and snapshot["replayable"] is True
    elif kind == "boolean":
        valid = allow_numeric and type(value) is bool and snapshot["replayable"] is True
    elif kind in BOUNDS:
        low, high = BOUNDS[kind]
        valid = allow_numeric and type(value) is int and low <= value <= high and snapshot["replayable"] is True
    elif kind == "exception-type":
        valid = isinstance(value, str) and value in EXCEPTIONS and snapshot["replayable"] is True
    else:
        valid = False
    if not valid:
        raise ValueError("invalid or unreviewed snapshot")


EXCEPTIONS = {"System." + name for name in (
    "ArgumentException", "ArgumentNullException", "ArgumentOutOfRangeException",
    "InvalidOperationException", "ObjectDisposedException", "NotSupportedException",
    "NotImplementedException", "NullReferenceException", "IndexOutOfRangeException",
    "InvalidCastException", "FormatException", "OverflowException", "Exception",
    "ComponentModel.InvalidEnumArgumentException", "Runtime.InteropServices.COMException",
    "DirectoryServices.DirectoryServicesCOMException",
    "DirectoryServices.AccountManagement.PrincipalOperationException",
    "DirectoryServices.AccountManagement.PrincipalServerDownException",
    "DirectoryServices.AccountManagement.MultipleMatchesException",
    "DirectoryServices.AccountManagement.NoMatchingPrincipalException",
    "DirectoryServices.AccountManagement.PasswordException")}
EXCEPTIONS.update(name.rsplit(".", 1)[-1] for name in tuple(EXCEPTIONS))


def collect(directory):
    paths = sorted(directory.glob("*.jsonl"))
    if not paths:
        raise ValueError("no suite capture files")
    methods, origins = collections.Counter(), collections.Counter()
    total = portable_shapes = redacted = 0
    assemblies = set()
    executions = set()
    for path in paths:
        begin, observations = load(path)
        if begin["execution"] in executions:
            raise ValueError("duplicate execution identity across capture files")
        executions.add(begin["execution"])
        methods[begin["testMethod"]] += 1
        assemblies.add(begin["provenance"]["assemblySha256"])
        for row in observations:
            total += 1
            origins[row["origin"]] += 1
            values = [row["value"]] + ([row["other"]] if row["other"] is not None else [])
            if all(v["replayable"] for v in values):
                portable_shapes += 1
            else:
                redacted += 1
    return {"schemaVersion": 1, "executions": len(paths), "methods": len(methods),
            "observations": total, "origins": dict(origins),
            "scalarShapeCandidates": portable_shapes, "redactedObservations": redacted,
            "assemblyCount": len(assemblies), "oracleAdmission": "none",
            "warning": "Scalar shape is not stable behavior, authenticated provenance, test pass, or portable replay coverage."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    try:
        print(json.dumps(collect(args.directory), indent=2))
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        parser.exit(2, "Capture validation failed; no capture values were printed.\n")


if __name__ == "__main__":
    main()
