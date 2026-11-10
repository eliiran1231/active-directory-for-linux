#!/usr/bin/env python3
"""Capture exactly the reviewed 80 detached rows on Windows, privately.

No live directory operation, arbitrary filter/arguments, upload, elective raw
retention, fixture promotion or replay is offered. Unverified process termination
retains the private workspace and forbids package creation for safe inspection.
--check-only works on other platforms.
The operator must secure a pre-created local directory with a private ACL.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import ntpath
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
PROJECT = pathlib.Path("tests/AdForLinux.DifferentialTests/AdForLinux.DifferentialTests.csproj")
ASSEMBLY = "AdForLinux.DifferentialTests.dll"
FRAMEWORKS = {"net8.0-windows": "8", "net10.0-windows": "10"}
MARKER = "ADFL_SUITE_EXECUTION_V1: "
NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
MAX_RAW_BYTES = 32 * 1024 * 1024

# Execution admission is deliberately separate from the privacy manifest.
# Expanding it requires an explicit source review, not another numeric site.
REVIEWED_METHODS = frozenset({
    'AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset',
    'AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft',
    'AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations',
    'AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter',
    'AdForLinux.DifferentialTests.CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers',
    'AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft',
    'AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft',
    'AdForLinux.DifferentialTests.CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft',
})
REVIEWED_FILES = frozenset({
    'tests/AdForLinux.DifferentialTests/CompatibilitySearcherStateComparisonTests.cs',
    'tests/AdForLinux.DifferentialTests/CompatibilitySynchronizationComparisonTests.cs',
    'tests/AdForLinux.DifferentialTests/CompatibilityVlvStateComparisonTests.cs',
})

spec = importlib.util.spec_from_file_location("detached_suite_collect", HERE / "collect.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
        return value.hexdigest()


def stable_id(kind, *parts):
    payload = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return kind + ":" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def plain_path(path, *, directory=False):
    """Reject reparse points in the entire existing path, not just the leaf."""
    require(path.is_absolute() and ".." not in path.parts, "absolute, non-traversing path required")
    require(not str(path).startswith(("\\\\", "//")), "local path required")
    for entry in reversed((path, *path.parents)):
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info, "st_file_attributes", 0) & 0x400,
                "symlinks and reparse points are not allowed")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            "unexpected path type")
    if not directory:
        require(info.st_nlink == 1, "hard-linked files are not allowed")
    return path


def load_contract(repo=REPOSITORY):
    manifest_path = repo / "tests/differential-replay/suite-wide/numeric-sites.json"
    cases_path = repo / "tests/differential-replay/suite-wide/detached-cases.json"
    manifest = json.loads(plain_path(manifest_path).read_text(encoding="utf-8"),
                          object_pairs_hook=collector.unique_object)
    contract = json.loads(plain_path(cases_path).read_text(encoding="utf-8"),
                          object_pairs_hook=collector.unique_object)
    require(manifest.get("schemaVersion") == 2, "unsupported source manifest")
    require(contract.get("schemaVersion") == 1 and contract.get("caseCount") == 80,
            "unsupported detached case contract")
    cases = contract["cases"]
    require(isinstance(cases, list) and len(cases) == 80 and
            all(isinstance(name, str) for name in cases) and len(set(cases)) == 80,
            "detached case contract must have exactly 80 unique names")
    methods = {name.split("(", 1)[0] for name in cases}
    require(len(methods) == 8 and all(re.fullmatch(r"AdForLinux\.DifferentialTests\.[A-Za-z_]\w*\.[A-Za-z_]\w*", method)
                                    for method in methods), "invalid detached methods")
    require(methods == REVIEWED_METHODS, "case contract expands or changes reviewed execution admission")
    sites = set()
    files = {}
    for entry in manifest["files"]:
        collector.exact_fields(entry, "path sha256")
        require(re.fullmatch(r"tests/AdForLinux\.DifferentialTests/[A-Za-z_]\w*\.cs", entry["path"]) is not None and
                re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                "invalid source hash entry")
        require(entry["path"] not in files, "duplicate source hash entry")
        files[entry["path"]] = entry["sha256"]
        require(digest(plain_path(repo / entry["path"])) == entry["sha256"],
                "reviewed source hash mismatch")
    require(set(files) == REVIEWED_FILES, "exact reviewed source files required")
    for site in manifest["sites"]:
        collector.exact_fields(site, "testMethod sourceFile sourceLine")
        method, filename, line = site["testMethod"], site["sourceFile"], site["sourceLine"]
        require(method in methods and filename == method.rsplit(".", 2)[1] + ".cs" and
                "tests/AdForLinux.DifferentialTests/" + filename in files and
                type(line) is int and line > 0, "invalid reviewed source site")
        key = (method, filename, line)
        require(key not in sites, "duplicate reviewed source site")
        sites.add(key)
    require({site[0] for site in sites} == methods, "method contract and source manifest differ")
    require(manifest == collector.NUMERIC_MANIFEST, "collector manifest differs from runner manifest")
    return {"cases": sorted(cases), "methods": sorted(methods), "sites": sites,
            "files": dict(sorted(files.items())), "manifestSha256": digest(manifest_path),
            "caseContractSha256": digest(cases_path)}


def clean_commit(repo, expected=None):
    """Never expose Git diagnostics or filenames, and never read environment settings."""
    def git(*args):
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
        require(result.returncode == 0, "Git provenance check failed")
        return result.stdout
    commit = git("rev-parse", "HEAD").decode("ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "unsupported source commit")
    if expected is not None:
        require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None and commit == expected,
                "source commit does not match requested commit")
    require(not git("status", "--porcelain=v1", "--untracked-files=all").strip(),
            "capture requires a clean committed checkout")
    return commit


def child_environment(parent, capture_directory):
    # Filter keys BEFORE indexing; even discarded AD_* values are not read.
    # Discard inherited instrumentation toggles too, including other recorders.
    child = {key: parent[key] for key in parent
             if not key.upper().startswith(("AD_", "ADFL_"))}
    child["ADFL_OFFLINE_TESTS"] = "1"
    child["ADFL_SUITE_CAPTURE_DIRECTORY"] = str(capture_directory)
    return child


def command(repo, framework, contract, results, source_commit):
    require(framework in FRAMEWORKS, "unsupported target framework")
    require(set(contract["methods"]) == REVIEWED_METHODS and len(contract["methods"]) == 8,
            "exact method contract required")
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None, "verified commit required for build")
    expression = "|".join("FullyQualifiedName=" + method for method in contract["methods"])
    return ["dotnet", "test", str(repo / PROJECT), "--configuration", "Release",
            "--framework", framework, "--no-restore", "-p:SourceRevisionId=" + source_commit,
            "-p:IncludeSourceRevisionInInformationalVersion=true", "--filter", expression,
            "--results-directory", str(results), "--logger", "trx;LogFileName=detached.trx"]


class ProcessTreeTerminationUnverified(subprocess.SubprocessError):
    """No package/cleanup is safe while capture descendants might still run."""


TASKKILL_TIMEOUT = 10
TREE_EXIT_TIMEOUT = 10
ROOT_EXIT_TIMEOUT = 5


def system_taskkill():
    # Use Windows' system directory, never a PATH-selected helper.
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    require(0 < length < len(buffer), "cannot locate Windows termination helper")
    return str(pathlib.Path(buffer.value) / "taskkill.exe")


def terminate_tree(process, log):
    """Best-effort tree termination with bounded waits and explicit uncertainty.

    A zero taskkill /T /F status plus a bounded root-exit wait is the available
    confirmation. This is not a kernel job-object guarantee. Any helper failure,
    timeout or interruption is unverified, even if root-only fallback succeeds.
    """
    try:
        result = subprocess.run([system_taskkill(), "/PID", str(process.pid), "/T", "/F"],
                                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                check=False, timeout=TASKKILL_TIMEOUT)
        if result.returncode == 0:
            process.wait(timeout=TREE_EXIT_TIMEOUT)
            return True
    except BaseException:
        # A second cancellation must not skip the fail-closed uncertainty path.
        pass
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=ROOT_EXIT_TIMEOUT)
    except BaseException:
        pass
    # Root exit never proves descendant exit when /T could not be confirmed.
    return False


def run_child(args, *, cwd, env, log, timeout):
    """Run privately; attempt bounded tree cancellation and fail closed if unsure."""
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        return process.wait(timeout=timeout)
    except BaseException:
        if not terminate_tree(process, log):
            raise ProcessTreeTerminationUnverified("capture process-tree exit unverified") from None
        raise


def single(parent, tag):
    elements = parent.findall(NS + tag)
    require(len(elements) == 1, "missing or duplicate TRX element")
    return elements[0]


def guid(value):
    require(isinstance(value, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value),
        "invalid TRX identity")
    return value.lower()


def read_trx(path, contract, assembly_path):
    plain_path(path)
    require(path.stat().st_size <= MAX_RAW_BYTES, "TRX exceeds size limit")
    raw = path.read_bytes()
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "TRX declarations are not allowed")
    root = ET.fromstring(raw)
    require(root.tag == NS + "TestRun", "unsupported TRX format")
    summary = single(root, "ResultSummary")
    require(summary.get("outcome") in ("Completed", "Passed"), "test run did not pass")
    counters = single(summary, "Counters")
    for key in ("total", "executed", "passed"):
        require(counters.get(key) == "80", "TRX must pass exactly 80 rows")
    for key, value in counters.attrib.items():
        if key not in ("total", "executed", "passed"):
            require(value == "0" or key == "completed" and value == "80", "TRX has non-passing rows")
    definitions = single(root, "TestDefinitions")
    require(len(definitions) == 80, "wrong TRX definition count")
    defined = {}
    for test in definitions:
        require(test.tag == NS + "UnitTest", "unexpected TRX definition")
        identity = guid(test.get("id"))
        require(identity not in defined, "duplicate TRX test identity")
        method = single(test, "TestMethod")
        full_method = (method.get("className", "") + "." + method.get("name", ""))
        require(full_method in contract["methods"], "unselected method in TRX")
        require(ntpath.normcase(ntpath.normpath(method.get("codeBase", ""))) ==
                ntpath.normcase(ntpath.normpath(str(assembly_path))), "TRX assembly path mismatch")
        defined[identity] = (test.get("name"), full_method, guid(single(test, "Execution").get("id")))
    results = single(root, "Results")
    require(len(results) == 80, "wrong TRX row count")
    cases, markers, execution_ids, used_ids = {}, set(), set(), set()
    expected_names = set(contract["cases"])
    for result in results:
        require(result.tag == NS + "UnitTestResult" and result.get("outcome") == "Passed",
                "unexpected or non-passing TRX row")
        require(not result.findall(".//" + NS + "InnerResults"), "nested TRX rows are not allowed")
        name = result.get("testName")
        require(name in expected_names and name not in cases, "unexpected or duplicate TRX case name")
        identity, execution_id = guid(result.get("testId")), guid(result.get("executionId"))
        require(identity in defined and identity not in used_ids and execution_id not in execution_ids,
                "unbound or duplicate TRX row identity")
        used_ids.add(identity)
        execution_ids.add(execution_id)
        definition_name, method, definition_execution = defined[identity]
        require(name == definition_name and name.split("(", 1)[0] == method and
                execution_id == definition_execution, "TRX definition/result mismatch")
        stdout = single(single(result, "Output"), "StdOut")
        require(not list(stdout), "nested TRX output is not allowed")
        # Some TRX writers retain literal escaped newline boundaries. Handle
        # only these boundaries, never generic string/unicode unescaping.
        lines = re.split(r"\r\n|\n|\r|\\r\\n|\\n|\\r", stdout.text or "")
        candidates = [line for line in lines if "ADFL_SUITE_EXECUTION_V1" in line]
        require(len(candidates) == 1, "missing or duplicate capture marker")
        match = re.fullmatch(re.escape(MARKER) + r"([0-9a-f]{32})", candidates[0])
        require(match is not None, "invalid capture marker")
        marker = match.group(1)
        require(marker not in markers, "capture marker reused by multiple cases")
        markers.add(marker)
        cases[name] = marker
    require(set(cases) == expected_names and used_ids == set(defined), "incomplete TRX case binding")
    return cases


def validate_package(capture_directory, trx, contract, framework, commit, assembly_path):
    """Validate every raw record before copying ONLY Microsoft snapshots."""
    bindings = read_trx(trx, contract, assembly_path)
    assembly_hash = digest(plain_path(assembly_path))
    captures = {}
    provenance = None
    plain_path(capture_directory, directory=True)
    paths = list(capture_directory.iterdir())
    require(len(paths) == 80, "capture directory must contain exactly 80 executions")
    for path in paths:
        require(re.fullmatch(r"[0-9a-f]{32}\.jsonl", path.name) is not None,
                "unexpected capture filename")
        plain_path(path)
        require(path.stat().st_size <= MAX_RAW_BYTES, "capture exceeds size limit")
        begin, rows = collector.load(path)
        execution = begin["execution"]
        require(path.stem == execution and execution not in captures, "capture file/execution mismatch")
        require(begin["testMethod"] in contract["methods"] and rows, "unexpected or empty capture")
        current = begin["provenance"]
        major = FRAMEWORKS[framework]
        require(current["target"] == ".NETCoreApp,Version=v" + major + ".0" and
                current["runtime"].startswith(".NET " + major + ".") and
                current["commit"] == commit and current["offlineGuard"] is True and
                current["assemblySha256"] == assembly_hash and current["sdk"] is not None,
                "capture build/framework/guard provenance mismatch")
        require(provenance is None or provenance == current, "mixed capture provenance")
        provenance = current
        for row in rows:
            require((begin["testMethod"], row["sourceFile"], row["sourceLine"]) in contract["sites"],
                    "capture contains an unreviewed detached source site")
        captures[execution] = (begin, rows)
    require(set(bindings.values()) == set(captures), "TRX and capture files are not a bijection")
    cases = []
    total = scalar = opaque = excluded = 0
    for name in contract["cases"]:
        begin, rows = captures[bindings[name]]
        require(begin["testMethod"] == name.split("(", 1)[0], "case marker binds the wrong method")
        case_id = stable_id("case-v1", name)
        occurrences, observations = collections.Counter(), []
        for row in rows:
            if row["origin"] != "explicit-microsoft-comparison":
                excluded += 1
                continue
            site_id = stable_id("site-v1", begin["testMethod"], row["sourceFile"],
                                row["sourceMember"], row["sourceLine"], row["role"])
            occurrences[site_id] += 1
            snapshot = dict(row["value"])
            observations.append({"observationId": stable_id("observation-v1", case_id, site_id, occurrences[site_id]),
                "sourceSiteId": site_id, "sourceFile": row["sourceFile"], "sourceMember": row["sourceMember"],
                "sourceLine": row["sourceLine"], "sourceSequence": row["sequence"],
                "siteOccurrence": occurrences[site_id], "role": row["role"], "microsoft": snapshot})
            total += 1
            scalar += snapshot["replayable"] is True
            opaque += snapshot["replayable"] is False
        require(observations, "case has no explicitly Microsoft observations")
        require(any(row["microsoft"]["replayable"] for row in observations),
                "case has no non-redacted Microsoft scalar candidates")
        cases.append({"caseId": case_id, "caseName": name, "testMethod": begin["testMethod"],
                      "observations": observations})
    return {"schemaVersion": 1, "status": "unvalidated-not-replayable", "oracleAdmission": "none",
            "classification": "private-detached-microsoft-observations", "framework": framework,
            "sourceCommit": commit, "sourceFiles": contract["files"],
            "numericManifestSha256": contract["manifestSha256"], "caseContractSha256": contract["caseContractSha256"],
            "provenance": provenance, "caseBinding": "exact-TRX-name-to-capture-marker-bijection",
            "caseCount": 80, "methodCount": 8, "observationCount": total,
            "scalarShapeCandidateCount": scalar, "opaqueObservationCount": opaque,
            "excludedUnverifiedOperandCount": excluded, "cases": cases}


def private_paths(private_directory, output, repo):
    reserved = {"CON", "PRN", "AUX", "NUL", *("COM" + str(n) for n in range(1, 10)),
                *("LPT" + str(n) for n in range(1, 10))}
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", output.name) is not None and
            output.name.split(".", 1)[0].upper() not in reserved,
            "output requires a simple non-device .json filename")
    plain_path(private_directory, directory=True)
    require(not private_directory.is_relative_to(repo), "private directory must be outside the repository")
    require(output.is_absolute() and ".." not in output.parts and output.is_relative_to(private_directory),
            "output must be inside the private directory")
    plain_path(output.parent, directory=True)
    require(not os.path.lexists(output), "output already exists; refusing to overwrite")


def write_package(output, package):
    # Exclusive creation: never overwrite or follow a destination symlink.
    created = False
    try:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            json.dump(package, stream, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise


def windows_host():
    return os.name == "nt"


def capture(private_directory, output, framework, *, source_commit=None, timeout=900,
            repo=REPOSITORY, parent_environment=None, execute=None):
    require(windows_host(), "fresh Microsoft capture requires Windows")
    require(framework in FRAMEWORKS and type(timeout) is int and 1 <= timeout <= 7200,
            "invalid framework or timeout")
    private_paths(private_directory, output, repo)
    contract = load_contract(repo)
    commit = clean_commit(repo, source_commit)
    package = None
    termination_unverified = False
    raw = pathlib.Path(tempfile.mkdtemp(prefix="adfl-detached-", dir=private_directory))
    try:
        captures, results = raw / "captures", raw / "results"
        captures.mkdir()
        results.mkdir()
        env = child_environment(os.environ if parent_environment is None else parent_environment, captures)
        with (raw / "process.log").open("xb") as log:
            code = (run_child if execute is None else execute)(command(repo, framework, contract, results, commit),
                cwd=repo, env=env, log=log, timeout=timeout)
        require(code == 0, "dotnet test failed; raw diagnostics are private and will be deleted")
        require(list(results.glob("*.trx")) == [results / "detached.trx"], "missing or extra TRX result")
        require(clean_commit(repo, commit) == commit and load_contract(repo) == contract,
                "source changed during capture")
        assembly = repo / PROJECT.parent / "bin/Release" / framework / ASSEMBLY
        package = validate_package(captures, results / "detached.trx", contract, framework, commit, assembly)
    except ProcessTreeTerminationUnverified:
        termination_unverified = True
        raise
    finally:
        # Never race deletion against possible surviving descendants. Retain
        # only the already-private workspace for explicit operator inspection.
        # There is no user-selectable raw-retention mode and no package output.
        if not termination_unverified:
            shutil.rmtree(raw)
    private_paths(private_directory, output, repo)
    write_package(output, package)
    return {key: package[key] for key in ("status", "caseCount", "methodCount", "observationCount",
                                         "scalarShapeCandidateCount", "opaqueObservationCount")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", choices=sorted(FRAMEWORKS), default="net8.0-windows")
    parser.add_argument("--private-directory", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--private-acl-confirmed", action="store_true",
                        help="attest that only authorized local accounts can access the private directory")
    parser.add_argument("--source-commit", help="optional exact 40-character HEAD commit to require")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--check-only", action="store_true", help="check source hashes and exact row/method contract; run nothing")
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            contract = load_contract()
            if args.source_commit is not None:
                clean_commit(REPOSITORY, args.source_commit)
            print(json.dumps({"status": "checked-no-execution", "caseCount": len(contract["cases"]),
                              "methodCount": len(contract["methods"])}))
            return 0
        require(args.private_directory is not None and args.output is not None and args.private_acl_confirmed,
                "private directory, output, and private ACL attestation are required")
        result = capture(args.private_directory, args.output, args.framework,
                         source_commit=args.source_commit, timeout=args.timeout)
        print(json.dumps(result, sort_keys=True))
        return 0
    except ProcessTreeTerminationUnverified:
        print("Capture process-tree exit could not be verified. No package was created. "
              "Inspect remaining capture processes and adfl-detached-* directories inside "
              "the supplied private directory before cleanup.", file=__import__("sys").stderr)
        return 2
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, ET.ParseError,
            subprocess.SubprocessError):
        # No exception details: parser errors and child output may contain values.
        print("Detached capture failed. No observations or process diagnostics were printed. "
              "Any cleanup failure leaves raw files only inside the supplied private directory.", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
