"""Mocked detached runner tests: no dotnet, Windows host or directory needed."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("suite_detached", HERE / "detached.py")
detached = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detached)


class DetachedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.captures = self.root / "captures"
        self.captures.mkdir()
        self.trx = self.root / "detached.trx"
        self.assembly = self.root / detached.ASSEMBLY
        self.assembly.write_bytes(b"synthetic-test-assembly-not-Microsoft")
        self.commit = "c" * 40
        self.contract = detached.load_contract()
        self.create_fixture()

    def create_fixture(self, framework="net8.0-windows", marker_offset=0):
        self.tree = ET.Element(detached.NS + "TestRun")
        self.results = ET.SubElement(self.tree, detached.NS + "Results")
        self.definitions = ET.SubElement(self.tree, detached.NS + "TestDefinitions")
        summary = ET.SubElement(self.tree, detached.NS + "ResultSummary", outcome="Completed")
        ET.SubElement(summary, detached.NS + "Counters", total="80", executed="80", passed="80", failed="0", notExecuted="0")
        self.records = {}
        for index, name in enumerate(self.contract["cases"], 1):
            marker = format(index + marker_offset, "032x")
            test_id = "00000000-0000-0000-0000-" + format(index, "012x")
            execution_id = "11111111-0000-0000-0000-" + format(index, "012x")
            method = name.split("(", 1)[0]
            test = ET.SubElement(self.definitions, detached.NS + "UnitTest", id=test_id, name=name)
            ET.SubElement(test, detached.NS + "Execution", id=execution_id)
            cls, member = method.rsplit(".", 1)
            ET.SubElement(test, detached.NS + "TestMethod", className=cls, name=member, codeBase=str(self.assembly))
            result = ET.SubElement(self.results, detached.NS + "UnitTestResult", testName=name, testId=test_id,
                                   executionId=execution_id, outcome="Passed")
            output = ET.SubElement(result, detached.NS + "Output")
            ET.SubElement(output, detached.NS + "StdOut").text = "ordinary private output, never copied\n" + detached.MARKER + marker + "\n"
            site = sorted(site for site in self.contract["sites"] if site[0] == method)[0]
            major = detached.FRAMEWORKS[framework]
            provenance = {"capturePolicy": "redacted-scalars-v2", "assemblySha256": detached.digest(self.assembly),
                "os": "Microsoft Windows 10.0.1", "target": ".NETCoreApp,Version=v" + major + ".0",
                "architecture": "X64", "runtime": ".NET " + major + ".0.1", "sdk": "10.0.100",
                "commit": self.commit, "offlineGuard": True,
                "microsoftDirectoryServices": "9.0.0.0", "microsoftAccountManagement": "9.0.0.0"}
            rows = [
                {"kind": "begin", "schemaVersion": 1, "execution": marker, "testMethod": method,
                 "source": "existing-windows-differential-suite", "provenance": provenance},
                {"kind": "observation", "schemaVersion": 1, "execution": marker, "sequence": 1,
                 "sourceFile": site[1], "sourceMember": member, "sourceLine": site[2], "role": "value",
                 "origin": "explicit-microsoft-comparison", "value": {"type": "int32", "value": 7, "replayable": True},
                 "other": {"type": "int32", "value": 987654321, "replayable": True}},
                {"kind": "end", "schemaVersion": 1, "execution": marker, "observations": 1,
                 "status": "body-finished-outcome-unverified"}]
            self.records[marker] = rows
        self.save()

    def save(self):
        ET.ElementTree(self.tree).write(self.trx, encoding="utf-8", xml_declaration=True)
        for path in self.captures.iterdir():
            path.unlink()
        for marker, rows in self.records.items():
            (self.captures / (marker + ".jsonl")).write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    def validate(self, framework="net8.0-windows"):
        return detached.validate_package(self.captures, self.trx, self.contract, framework, self.commit, self.assembly)

    def first_rows(self):
        return next(iter(self.records.values()))

    def test_checked_contract_has_eight_exact_methods_and_eighty_names(self):
        result = self.contract
        self.assertEqual(8, len(result["methods"]))
        self.assertEqual(80, len(result["cases"]))
        self.assertEqual(3, len(result["files"]))
        args = detached.command(detached.REPOSITORY, "net8.0-windows", result, self.root, self.commit)
        expression = args[args.index("--filter") + 1]
        self.assertEqual({"FullyQualifiedName=" + method for method in result["methods"]}, set(expression.split("|")))
        self.assertNotIn("~", expression)
        self.assertNotIn("--no-build", args)
        self.assertIn("--no-restore", args)
        self.assertIn(str(detached.REPOSITORY / detached.PROJECT), args)
        self.assertEqual("Release", args[args.index("--configuration") + 1])

    def test_check_only_runs_no_git_or_dotnet(self):
        with mock.patch.object(detached.subprocess, "run", side_effect=AssertionError("process launched")), \
                mock.patch.object(detached, "run_child", side_effect=AssertionError("dotnet launched")), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(0, detached.main(["--check-only"]))
        self.assertEqual({"status": "checked-no-execution", "caseCount": 80, "methodCount": 8}, json.loads(stdout.getvalue()))

    def test_unknown_cli_filters_and_dotnet_arguments_are_rejected(self):
        for option in ("--filter", "--no-build", "--dotnet-args", "--keep-raw"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                detached.main([option])

    def test_changed_contract_and_manifest_cannot_expand_execution_admission(self):
        path = HERE / "detached-cases.json"
        contract = json.loads(path.read_text())
        old = self.contract["methods"][0]
        new = old.rsplit(".", 1)[0] + ".InjectedMethod"
        contract["cases"] = [name.replace(old, new) for name in contract["cases"]]
        manifest = copy.deepcopy(detached.collector.NUMERIC_MANIFEST)
        for site in manifest["sites"]:
            if site["testMethod"] == old:
                site["testMethod"] = new
        original = pathlib.Path.read_text
        def read_text(candidate, *args, **kwargs):
            if candidate.name == "detached-cases.json":
                return json.dumps(contract)
            if candidate.name == "numeric-sites.json":
                return json.dumps(manifest)
            return original(candidate, *args, **kwargs)
        with mock.patch.object(pathlib.Path, "read_text", read_text), \
                mock.patch.object(detached.collector, "NUMERIC_MANIFEST", manifest):
            with self.assertRaisesRegex(ValueError, "execution admission"):
                detached.load_contract()
        altered = dict(self.contract, methods=[new if method == old else method for method in self.contract["methods"]])
        with self.assertRaises(ValueError):
            detached.command(detached.REPOSITORY, "net8.0-windows", altered, self.root, self.commit)

    def test_literal_escaped_newlines_bind_markers_without_general_unescaping(self):
        for separator in (r"\r\n", r"\n", "\r\n"):
            self.create_fixture()
            for result in self.results:
                stdout = result.find(detached.NS + "Output/" + detached.NS + "StdOut")
                stdout.text = stdout.text.replace("\n", separator)
            self.save()
            self.assertEqual(80, self.validate()["caseCount"])

    def test_windows_device_names_ads_and_odd_output_suffixes_are_refused(self):
        for name in ("CON.json", "nul.json", "PRN.extra.json", "COM1.json", "LPT9.foo.json",
                     "output:private.json", "output.json ", "output.json.", "out.txt", "out name.json"):
            with self.assertRaises(ValueError):
                detached.private_paths(self.root, self.root / name, detached.REPOSITORY)
        detached.private_paths(self.root, self.root / "detached-net8.v1.json", detached.REPOSITORY)

    def test_source_hash_mismatch_refuses_before_launch(self):
        with mock.patch.object(detached, "digest", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                detached.load_contract()

    def test_numeric_manifest_alone_cannot_expand_admission(self):
        original = detached.collector.NUMERIC_MANIFEST
        for mutate in (lambda value: value["sites"].append({"testMethod": "AdForLinux.DifferentialTests.LiveTests.Live", "sourceFile": "LiveTests.cs", "sourceLine": 1}),
                       lambda value: value["files"].append({"path": "tests/windows/AdForLinux.DifferentialTests/LiveTests.cs", "sha256": "a" * 64}),
                       lambda value: value["sites"].pop()):
            bad = copy.deepcopy(original)
            mutate(bad)
            with mock.patch.object(detached.collector, "NUMERIC_MANIFEST", bad):
                with self.assertRaises(ValueError):
                    detached.load_contract()

    def test_environment_never_reads_ad_settings_and_never_mutates_parent(self):
        class Environment(dict):
            def __getitem__(self, key):
                if key.upper().startswith(("AD_", "ADFL_")):
                    raise AssertionError("read protected environment value")
                return super().__getitem__(key)
        parent = Environment(PATH="ordinary", AD_PASSWORD="must not read", ad_server="must not read",
                             ADFL_OTHER_CAPTURE="must not read", adfl_offline_tests="must not read")
        keys = set(parent)
        child = detached.child_environment(parent, self.captures)
        self.assertEqual(keys, set(parent))
        self.assertEqual({"PATH": "ordinary", "ADFL_OFFLINE_TESTS": "1",
                          "ADFL_SUITE_CAPTURE_DIRECTORY": str(self.captures)}, child)

    def test_clean_commit_rejects_wrong_head_and_dirty_or_untracked_inputs(self):
        def returned(payload):
            return subprocess.CompletedProcess([], 0, stdout=payload, stderr=b"private diagnostics")
        for outputs, expected in (([returned((self.commit + "\n").encode())], "b" * 40),
                                  ([returned((self.commit + "\n").encode()), returned(b" M private.cs")], None),
                                  ([returned((self.commit + "\n").encode()), returned(b"?? injected.cs")], None)):
            with mock.patch.object(detached.subprocess, "run", side_effect=outputs):
                with self.assertRaises(ValueError):
                    detached.clean_commit(detached.REPOSITORY, expected)
        with mock.patch.object(detached.subprocess, "run", side_effect=[returned(self.commit.encode()), returned(b"")]):
            self.assertEqual(self.commit, detached.clean_commit(detached.REPOSITORY, self.commit))

    def test_package_is_ms_only_sorted_and_not_replayable(self):
        package = self.validate()
        self.assertEqual("unvalidated-not-replayable", package["status"])
        self.assertEqual("none", package["oracleAdmission"])
        self.assertEqual(80, package["observationCount"])
        self.assertEqual(self.contract["cases"], [case["caseName"] for case in package["cases"]])
        encoded = json.dumps(package)
        self.assertNotIn("987654321", encoded)
        self.assertNotIn("ordinary private output", encoded)
        self.assertNotIn('"other"', encoded)
        self.assertNotIn('"execution"', encoded)
        self.assertEqual(80, len({case["caseId"] for case in package["cases"]}))
        self.assertTrue(all(case["observations"][0]["sourceSiteId"].startswith("site-v1:") for case in package["cases"]))

    def test_random_execution_ids_and_input_order_do_not_change_package(self):
        first = self.validate()
        self.create_fixture(marker_offset=100)
        self.results[:] = list(reversed(self.results[:]))
        self.definitions[:] = list(reversed(self.definitions[:]))
        self.save()
        self.assertEqual(first, self.validate())

    def test_net10_has_matching_runtime_target(self):
        self.create_fixture(framework="net10.0-windows")
        self.assertEqual("net10.0-windows", self.validate("net10.0-windows")["framework"])
        with self.assertRaises(ValueError):
            self.validate("net8.0-windows")

    def test_duplicate_missing_extra_failed_skipped_or_renamed_case_fails(self):
        mutations = [lambda: self.results.remove(self.results[-1]),
                     lambda: self.results.append(copy.deepcopy(self.results[0])),
                     lambda: self.results[0].set("testName", self.results[1].get("testName")),
                     lambda: self.results[0].set("testName", "AdForLinux.DifferentialTests.Live.Test"),
                     lambda: self.results[0].set("outcome", "Failed"),
                     lambda: self.results[0].set("outcome", "NotExecuted")]
        for mutation in mutations:
            self.create_fixture()
            mutation()
            self.save()
            with self.assertRaises(ValueError):
                self.validate()

    def test_missing_duplicate_malformed_reused_and_cross_method_markers_fail(self):
        def stdout(index):
            return self.results[index].find(detached.NS + "Output/" + detached.NS + "StdOut")
        for value in ("no marker", detached.MARKER + "a" * 32 + "\n" + detached.MARKER + "b" * 32,
                      detached.MARKER + "X" * 32, "prefix " + detached.MARKER + "a" * 32,
                      detached.MARKER + "0" * 32):
            self.create_fixture()
            stdout(0).text = value
            self.save()
            with self.assertRaises(ValueError):
                self.validate()
        self.create_fixture()
        stdout(0).text = stdout(1).text
        self.save()
        with self.assertRaises(ValueError):
            self.validate()
        self.create_fixture()
        stdout(0).text, stdout(79).text = stdout(79).text, stdout(0).text
        self.save()
        with self.assertRaisesRegex(ValueError, "wrong method"):
            self.validate()

    def test_wrong_definition_assembly_and_summary_counts_fail(self):
        mutations = [lambda: self.definitions[0].find(detached.NS + "TestMethod").set("codeBase", "/wrong.dll"),
                     lambda: self.definitions[0].find(detached.NS + "TestMethod").set("name", "Live"),
                     lambda: self.tree.find(detached.NS + "ResultSummary/" + detached.NS + "Counters").set("passed", "79"),
                     lambda: self.tree.find(detached.NS + "ResultSummary").set("outcome", "Failed")]
        for mutation in mutations:
            self.create_fixture()
            mutation()
            self.save()
            with self.assertRaises(ValueError):
                self.validate()

    def test_empty_incomplete_duplicate_unknown_field_wrong_name_captures_fail(self):
        mutations = [lambda rows: rows.pop(), lambda rows: rows[1].update(sequence=5),
                     lambda rows: rows[1].update(unreviewed="private"),
                     lambda rows: rows[0].update(execution="f" * 32),
                     lambda rows: (rows.pop(1), rows[-1].update(observations=0)),
                     lambda rows: rows[1].update(sourceLine=999999),
                     lambda rows: rows[1]["other"].update(type="string", value="private")]
        for mutation in mutations:
            self.create_fixture()
            mutation(self.first_rows())
            self.save()
            with self.assertRaises(ValueError):
                self.validate()
        self.create_fixture()
        (self.captures / "extra.jsonl").write_text("private")
        with self.assertRaises(ValueError):
            self.validate()
        self.create_fixture()
        next(self.captures.iterdir()).unlink()
        with self.assertRaises(ValueError):
            self.validate()

    def test_mixed_or_wrong_provenance_is_refused(self):
        for key, value in (("offlineGuard", False), ("commit", "d" * 40), ("commit", None),
                           ("assemblySha256", "e" * 64), ("target", ".NETCoreApp,Version=v10.0"),
                           ("runtime", ".NET 10.0.1"), ("os", "Linux"), ("sdk", None),
                           ("architecture", "Arm64")):
            self.create_fixture()
            self.first_rows()[0]["provenance"][key] = value
            self.save()
            with self.assertRaises(ValueError):
                self.validate()

    def test_redacted_observations_reported_but_all_redacted_case_rejected(self):
        rows = self.first_rows()
        extra = copy.deepcopy(rows[1])
        extra["sequence"] = 2
        extra["value"] = {"type": "redacted", "value": None, "replayable": False}
        rows.insert(2, extra)
        rows[-1]["observations"] = 2
        self.save()
        package = self.validate()
        self.assertEqual(1, package["opaqueObservationCount"])
        self.assertEqual(80, package["scalarShapeCandidateCount"])
        first, second = package["cases"][0]["observations"]
        self.assertEqual(first["sourceSiteId"], second["sourceSiteId"])
        self.assertNotEqual(first["observationId"], second["observationId"])
        rows[1]["value"] = extra["value"]
        self.save()
        with self.assertRaisesRegex(ValueError, "non-redacted"):
            self.validate()

    def test_unverified_assertion_operands_are_not_microsoft_expected_values(self):
        rows = self.first_rows()
        extra = copy.deepcopy(rows[1])
        extra.update(sequence=2, origin="assertion-operand-unverified", role="assert-equal-expected", other=None)
        extra["value"]["value"] = 123456789
        rows.insert(2, extra)
        rows[-1]["observations"] = 2
        self.save()
        package = self.validate()
        self.assertEqual(1, package["excludedUnverifiedOperandCount"])
        self.assertNotIn("123456789", json.dumps(package))

    def test_xml_entity_declaration_is_rejected(self):
        self.trx.write_bytes(b'<!DOCTYPE x [<!ENTITY private "private">]>' + self.trx.read_bytes())
        with self.assertRaises(ValueError):
            self.validate()

    def test_paths_require_preexisting_private_local_non_link_directory_and_new_output(self):
        private = self.root / "private"
        private.mkdir()
        output = private / "package.json"
        detached.private_paths(private, output, detached.REPOSITORY)
        for bad_private, bad_output in ((pathlib.Path("relative"), output), (self.root / "missing", output),
                                        (private, self.root / "outside.json"),
                                        (detached.REPOSITORY, detached.REPOSITORY / "artifact.json")):
            with self.assertRaises((ValueError, OSError)):
                detached.private_paths(bad_private, bad_output, detached.REPOSITORY)
        output.write_text("do not overwrite")
        with self.assertRaises(ValueError):
            detached.private_paths(private, output, detached.REPOSITORY)
        self.assertEqual("do not overwrite", output.read_text())

    @unittest.skipIf(os.name == "nt", "symlink creation requires extra Windows privileges")
    def test_linked_directories_and_capture_files_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.captures, target_is_directory=True)
        with self.assertRaises(ValueError):
            detached.plain_path(linked, directory=True)
        path = next(self.captures.iterdir())
        target = self.root / "outside.jsonl"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.validate()

    def test_success_ordinary_failure_and_confirmed_timeout_cleanup_preserve_parent_env(self):
        for mode in ("success", "exit-failure", "timeout", "invalid"):
            private = self.root / mode
            private.mkdir()
            output = private / "package.json"
            original_env = {"PATH": "test", "AD_PASSWORD": "never inherited", "ADFL_OTHER": "never inherited"}
            before = original_env.copy()
            raw_dirs = []
            def execute(args, *, cwd, env, log, timeout):
                raw_dir = pathlib.Path(env["ADFL_SUITE_CAPTURE_DIRECTORY"]).parent
                raw_dirs.append(raw_dir)
                self.assertEqual("1", env["ADFL_OFFLINE_TESTS"])
                self.assertFalse(any(key.startswith("AD_") for key in env))
                self.assertNotIn("ADFL_OTHER", env)
                log.write(b"private build and test diagnostics")
                if mode == "timeout":
                    raise subprocess.TimeoutExpired(args, timeout)
                if mode == "exit-failure":
                    return 1
                for path in self.captures.iterdir():
                    shutil.copy2(path, raw_dir / "captures" / path.name)
                shutil.copy2(self.trx, raw_dir / "results/detached.trx")
                return 0
            validate = mock.Mock(return_value=self.validate())
            if mode == "invalid":
                validate.side_effect = ValueError("private detail")
            with mock.patch.object(detached, "windows_host", return_value=True), \
                    mock.patch.object(detached, "clean_commit", return_value=self.commit), \
                    mock.patch.object(detached, "validate_package", validate):
                if mode == "success":
                    result = detached.capture(private, output, "net8.0-windows", parent_environment=original_env, execute=execute)
                    self.assertEqual(80, result["caseCount"])
                    self.assertTrue(output.exists())
                else:
                    with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                        detached.capture(private, output, "net8.0-windows", parent_environment=original_env, execute=execute)
                    self.assertFalse(output.exists())
            self.assertEqual(before, original_env)
            self.assertEqual(1, len(raw_dirs))
            self.assertFalse(raw_dirs[0].exists())
            self.assertEqual([output] if mode == "success" else [], list(private.iterdir()))

    def test_tree_termination_requires_zero_helper_exit_and_bounded_root_wait(self):
        process = mock.Mock(pid=1234)
        log = io.BytesIO()
        with mock.patch.object(detached, "system_taskkill", return_value="SYSTEM/taskkill.exe"), \
                mock.patch.object(detached.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(detached.terminate_tree(process, log))
        self.assertEqual(["SYSTEM/taskkill.exe", "/PID", "1234", "/T", "/F"], run.call_args.args[0])
        self.assertEqual(detached.TASKKILL_TIMEOUT, run.call_args.kwargs["timeout"])
        process.wait.assert_called_once_with(timeout=detached.TREE_EXIT_TIMEOUT)
        process.kill.assert_not_called()

    def test_nonzero_or_timed_out_tree_kill_is_unverified_despite_root_exit(self):
        for helper_outcome in (mock.Mock(returncode=1), subprocess.TimeoutExpired("taskkill", 10),
                               OSError("private helper detail"), KeyboardInterrupt()):
            process = mock.Mock(pid=1234)
            process.poll.return_value = None
            with mock.patch.object(detached, "system_taskkill", return_value="SYSTEM/taskkill.exe"), \
                    mock.patch.object(detached.subprocess, "run") as run:
                if isinstance(helper_outcome, BaseException):
                    run.side_effect = helper_outcome
                else:
                    run.return_value = helper_outcome
                self.assertFalse(detached.terminate_tree(process, io.BytesIO()))
            process.kill.assert_called_once_with()
            process.wait.assert_called_once_with(timeout=detached.ROOT_EXIT_TIMEOUT)
            self.assertEqual(detached.TASKKILL_TIMEOUT, run.call_args.kwargs["timeout"])

    def test_missing_helper_or_stuck_root_cannot_trigger_unbounded_wait(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("root", 5)
        with mock.patch.object(detached, "system_taskkill", side_effect=ValueError("missing helper")), \
                mock.patch.object(detached.subprocess, "run") as run:
            self.assertFalse(detached.terminate_tree(process, io.BytesIO()))
        run.assert_not_called()
        process.wait.assert_called_once_with(timeout=detached.ROOT_EXIT_TIMEOUT)
        process.wait.reset_mock()
        with mock.patch.object(detached, "system_taskkill", return_value="SYSTEM/taskkill.exe"), \
                mock.patch.object(detached.subprocess, "run", return_value=mock.Mock(returncode=0)):
            self.assertFalse(detached.terminate_tree(process, io.BytesIO()))
        self.assertEqual([mock.call(timeout=detached.TREE_EXIT_TIMEOUT),
                          mock.call(timeout=detached.ROOT_EXIT_TIMEOUT)], process.wait.call_args_list)

    def test_run_child_preserves_cancellation_only_after_confirmed_tree_exit(self):
        for confirmed in (True, False):
            process = mock.Mock(pid=1234)
            process.wait.side_effect = subprocess.TimeoutExpired("dotnet", 900)
            with mock.patch.object(detached.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, create=True), \
                    mock.patch.object(detached.subprocess, "Popen", return_value=process), \
                    mock.patch.object(detached, "terminate_tree", return_value=confirmed):
                expected = subprocess.TimeoutExpired if confirmed else detached.ProcessTreeTerminationUnverified
                with self.assertRaises(expected):
                    detached.run_child(["dotnet", "test"], cwd=self.root, env={}, log=io.BytesIO(), timeout=900)

    def test_unverified_tree_retains_private_workspace_and_never_creates_package(self):
        private = self.root / "uncertain"
        private.mkdir()
        output = private / "package.json"
        environment = {"PATH": "test", "AD_PASSWORD": "never inherited"}
        before = dict(environment)
        def execute(args, *, cwd, env, log, timeout):
            log.write(b"private diagnostics")
            raise detached.ProcessTreeTerminationUnverified("PRIVATE-SENTINEL")
        with mock.patch.object(detached, "windows_host", return_value=True), \
                mock.patch.object(detached, "clean_commit", return_value=self.commit), \
                mock.patch.object(detached, "write_package") as write:
            with self.assertRaises(detached.ProcessTreeTerminationUnverified):
                detached.capture(private, output, "net8.0-windows", parent_environment=environment, execute=execute)
        write.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(before, environment)
        leftovers = list(private.iterdir())
        self.assertEqual(1, len(leftovers))
        self.assertTrue(leftovers[0].name.startswith("adfl-detached-"))
        self.assertTrue((leftovers[0] / "process.log").exists())

    def test_unverified_termination_message_requests_inspection_without_raw_details(self):
        with mock.patch.object(detached, "capture", side_effect=detached.ProcessTreeTerminationUnverified("PRIVATE-SENTINEL")), \
                contextlib.redirect_stderr(io.StringIO()) as stderr, contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(2, detached.main(["--private-directory", str(self.root), "--output", str(self.root / "out.json"), "--private-acl-confirmed"]))
        self.assertIn("could not be verified", stderr.getvalue())
        self.assertIn("No package", stderr.getvalue())
        self.assertNotIn("PRIVATE-SENTINEL", stdout.getvalue() + stderr.getvalue())
        self.assertEqual("", stdout.getvalue())

    def test_normal_execution_refuses_linux_before_launch(self):
        with mock.patch.object(detached, "windows_host", return_value=False), \
                mock.patch.object(detached, "run_child", side_effect=AssertionError("launched")):
            with self.assertRaisesRegex(ValueError, "Windows"):
                detached.capture(self.root, self.root / "package.json", "net8.0-windows")

    def test_failure_message_contains_no_raw_values_or_exception_details(self):
        with mock.patch.object(detached, "capture", side_effect=ValueError("PRIVATE-SENTINEL")), \
                contextlib.redirect_stderr(io.StringIO()) as stderr, contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(2, detached.main(["--private-directory", str(self.root), "--output", str(self.root / "out.json"), "--private-acl-confirmed"]))
        self.assertNotIn("PRIVATE-SENTINEL", stdout.getvalue() + stderr.getvalue())
        self.assertEqual("", stdout.getvalue())

    def test_package_write_does_not_overwrite_existing_target(self):
        output = self.root / "package.json"
        output.write_text("existing")
        with self.assertRaises(FileExistsError):
            detached.write_package(output, self.validate())
        self.assertEqual("existing", output.read_text())


if __name__ == "__main__":
    unittest.main()
