import copy
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("suite_collect", ROOT / "collect.py")
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)


class CaptureValidationTests(unittest.TestCase):
    def fixture(self):
        execution = "a" * 32
        method, source_file, source_line = sorted(collect.NUMERIC_SITES)[0]
        return [
            {"kind": "begin", "schemaVersion": 1, "execution": execution,
             "source": "existing-windows-differential-suite", "testMethod": method,
             "provenance": {"capturePolicy": "redacted-scalars-v2", "assemblySha256": "b" * 64,
                            "os": "Microsoft Windows 10.0.1", "target": ".NETCoreApp,Version=v8.0",
                            "architecture": "X64", "runtime": ".NET 8.0.1", "sdk": "10.0.100",
                            "commit": "c" * 40, "offlineGuard": True,
                            "microsoftDirectoryServices": "9.0.0.0", "microsoftAccountManagement": "9.0.0.0"}},
            {"kind": "observation", "schemaVersion": 1, "execution": execution, "sequence": 1,
             "sourceFile": source_file, "sourceMember": method.rsplit(".", 1)[-1], "sourceLine": source_line,
             "role": "value", "origin": "explicit-microsoft-comparison", "value": {"type": "int32", "value": 7, "replayable": True},
             "other": {"type": "redacted", "value": None, "replayable": False}},
            {"kind": "end", "schemaVersion": 1, "execution": execution, "observations": 1,
             "status": "body-finished-outcome-unverified"},
        ]

    def load(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "sample.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in records))
            return collect.load(path)

    def test_accepts_complete_redacted_capture_without_oracle_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "sample.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in self.fixture()))
            result = collect.collect(path.parent)
            self.assertEqual(1, result["observations"])
            self.assertEqual(1, result["redactedObservations"])
            self.assertEqual("none", result["oracleAdmission"])

    def test_duplicate_execution_files_cannot_inflate_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            payload = "\n".join(json.dumps(record) for record in self.fixture())
            (root / "first.jsonl").write_text(payload)
            (root / "copied.jsonl").write_text(payload)
            with self.assertRaisesRegex(ValueError, "duplicate execution identity"):
                collect.collect(root)

    def test_rejects_truncation_wrong_order_wrong_execution_and_false_pass(self):
        for mutation in (lambda r: r.pop(), lambda r: r[1].update(sequence=2),
                         lambda r: r[1].update(execution="c" * 32),
                         lambda r: r[2].update(status="Passed")):
            records = self.fixture()
            mutation(records)
            with self.assertRaises(ValueError):
                self.load(records)

    def test_rejects_wrong_platform_target_and_microsoft_version(self):
        for field, value in (("os", "Linux"), ("target", ".NETCoreApp,Version=v9.0"),
                             ("microsoftDirectoryServices", "8.0.0.0")):
            records = self.fixture()
            records[0]["provenance"][field] = value
            with self.assertRaises(ValueError):
                self.load(records)

    def test_rejects_arbitrary_string_or_object_payload(self):
        for snapshot in ({"type": "string", "value": "private", "replayable": True},
                         {"type": "exception-type", "value": "System.privateException", "replayable": True},
                         {"type": "redacted", "value": "private", "replayable": False},
                         {"type": "int32", "value": True, "replayable": True}):
            records = self.fixture()
            records[1]["value"] = snapshot
            with self.assertRaises(ValueError):
                self.load(records)

    def test_rejects_unknown_fields_at_every_level(self):
        for target in (lambda r: r[0], lambda r: r[0]["provenance"], lambda r: r[1],
                       lambda r: r[1]["value"], lambda r: r[2]):
            records = self.fixture()
            target(records)["private_extra"] = "must not be admitted"
            with self.assertRaises(ValueError):
                self.load(records)

    def test_rejects_missing_or_invalid_callsite_and_role(self):
        for field in ("sourceFile", "sourceMember", "sourceLine", "role", "origin", "value", "other"):
            records = self.fixture()
            del records[1][field]
            with self.assertRaises(ValueError):
                self.load(records)
        for field, value in (("sourceLine", 0), ("sourceLine", True), ("sourceLine", "20"),
                             ("role", "arbitrary"), ("sourceFile", "../secret.cs"),
                             ("sourceMember", "invalid member"), ("value", None),
                             ("origin", "assertion-operand-unverified")):
            records = self.fixture()
            records[1][field] = value
            with self.assertRaises(ValueError):
                self.load(records)

    def test_integer_widths_are_exact(self):
        for kind, (low, high) in collect.BOUNDS.items():
            for value in (low - 1, high + 1, True, "7", 7.0):
                with self.assertRaises(ValueError):
                    collect.validate_snapshot({"type": kind, "value": value, "replayable": True}, allow_numeric=True)
            for value in (low, high):
                collect.validate_snapshot({"type": kind, "value": value, "replayable": True}, allow_numeric=True)

    def test_numeric_and_boolean_values_require_exact_reviewed_site(self):
        for field, value in (("sourceLine", 1), ("sourceFile", "OtherTests.cs")):
            records = self.fixture()
            records[1][field] = value
            with self.assertRaises(ValueError):
                self.load(records)
        records = self.fixture()
        records[0]["testMethod"] = "Unreviewed.Test"
        with self.assertRaises(ValueError):
            self.load(records)
        for snapshot in ({"type": "int64", "value": 123456789, "replayable": True},
                         {"type": "boolean", "value": True, "replayable": True}):
            with self.assertRaises(ValueError):
                collect.validate_snapshot(snapshot)

    def runtime_numeric_sites(self):
        source = (ROOT.parents[3] / "tests/windows/AdForLinux.DifferentialTests/SuiteCapture.cs").read_text()
        block = re.search(r'HashSet<\(string TestMethod, string SourceFile, int SourceLine\)> NumericSites = new\(\)\s*\{(.*?)\};', source, re.S)
        self.assertIsNotNone(block)
        return source, {(method, file, int(line)) for method, file, line in
                        re.findall(r'\("([^"\n]+)", "([^"\n]+)", (\d+)\)', block.group(1))}

    def test_numeric_manifest_matches_reviewed_sources_and_exact_runtime_tuples(self):
        import hashlib
        repo = ROOT.parents[3]
        for entry in collect.NUMERIC_MANIFEST["files"]:
            self.assertEqual(entry["sha256"], hashlib.sha256((repo / entry["path"]).read_bytes()).hexdigest())
        source, runtime = self.runtime_numeric_sites()
        self.assertEqual(collect.NUMERIC_SITES, runtime)
        self.assertIn('NumericSites.Contains((session.Test, System.IO.Path.GetFileName(file), line))', source)
        self.assertNotIn('NumericTests', source)
        for kind in ('bool', 'long', 'Enum'):
            self.assertIn(kind + ' v when allowNumeric', source)

    def test_cross_family_and_cross_method_numeric_sites_are_refused(self):
        _, runtime = self.runtime_numeric_sites()
        # Each component is individually admitted, but the combined tuple is not.
        for method, source_file, line in tuple(collect.NUMERIC_SITES):
            for other_method, other_file, other_line in tuple(collect.NUMERIC_SITES):
                if other_file == source_file:
                    continue
                mixed = (method, other_file, other_line)
                self.assertNotIn(mixed, collect.NUMERIC_SITES)
                self.assertNotIn(mixed, runtime)
                records = self.fixture()
                records[0]["testMethod"] = method
                records[1]["sourceFile"] = other_file
                records[1]["sourceLine"] = other_line
                with self.assertRaises(ValueError):
                    self.load(records)
                break
        method = "AdForLinux.DifferentialTests.CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset"
        timeout = sorted(site for site in collect.NUMERIC_SITES if ".Timeout_boundary_" in site[0])[0]
        mixed = (method, timeout[1], timeout[2])
        self.assertNotIn(mixed, collect.NUMERIC_SITES)
        self.assertNotIn(mixed, runtime)
        records = self.fixture()
        records[0]["testMethod"] = method
        records[1]["sourceFile"] = timeout[1]
        records[1]["sourceLine"] = timeout[2]
        with self.assertRaises(ValueError):
            self.load(records)

    def test_detached_methods_link_capture_before_exercising_apis(self):
        repo = ROOT.parents[3]
        total = 0
        for entry in collect.NUMERIC_MANIFEST["files"]:
            source = (repo / entry["path"]).read_text()
            methods = re.findall(r'public void \w+\([^)]*\)\s*\{\s*SuiteCapture.LinkOutput\(_captureOutput\);', source)
            total += len(methods)
            self.assertEqual(len(re.findall(r'public void \w+\(', source)), len(methods))
            self.assertIn('ITestOutputHelper output', source)
        self.assertEqual(8, total)
        source = (repo / 'tests/windows/AdForLinux.DifferentialTests/SuiteCapture.cs').read_text()
        self.assertIn('output.WriteLine("ADFL_SUITE_EXECUTION_V1: " + session.Execution);', source)

    def test_rejects_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "sample.jsonl"
            text = "\n".join(json.dumps(r) for r in self.fixture())
            path.write_text(text.replace('"value": 7', '"value": 7, "value": 8'))
            with self.assertRaises(ValueError):
                collect.load(path)

    def test_equal_instrumentation_does_not_change_original_expression_text(self):
        repo = ROOT.parents[3]
        manifest = json.loads((ROOT / "instrumentation.json").read_text())
        sources = {site["file"] for site in manifest["sites"]}
        for name in sources:
            relative = "tests/windows/AdForLinux.DifferentialTests/" + name
            original = subprocess.check_output(["git", "show", manifest["baseline"] + ":" + relative.replace("tests/windows/", "tests/", 1)], cwd=repo, text=True)
            instrumented = (repo / relative).read_text()
            # Wrapper opening and trailing metadata are the only inserted tokens.
            # No operands are reevaluated or moved to a later assertion.
            restored = instrumented.replace("SuiteCapture.Expected(", "")
            restored = re.sub(r', "assert-equal-(?:expected|actual)", \d+\)', "", restored)
            self.assertEqual(original, restored, name)

    def test_existing_admitted_replay_sources_remain_unmodified(self):
        repo = ROOT.parents[3]
        manifest = json.loads((ROOT.parent / "results/manifest.json").read_text())
        for row in manifest["caseSources"]:
            original = subprocess.check_output(["git", "show", "33c25e4:" + row["path"].replace("tests/windows/", "tests/", 1)], cwd=repo)
            self.assertEqual(original, (repo / row["path"]).read_bytes())


if __name__ == "__main__":
    unittest.main()
