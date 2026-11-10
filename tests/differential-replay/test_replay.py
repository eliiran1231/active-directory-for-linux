#!/usr/bin/env python3
"""Parser and runner checks, not execution of the C# behavior cases."""
import copy
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import extract
import run
import structured

NS = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"


def example():
    """Test-only TRX built from retained Microsoft values, with an untrusted clone line."""
    fixture = json.loads((run.HERE / "results/run202-net8.0.json").read_text())
    root = ET.Element("{" + NS + "}TestRun")
    results = ET.SubElement(root, "{" + NS + "}Results")
    rows = copy.deepcopy(fixture["cases"])
    rows[extract.PREFIX + "FixtureRegistrationTests.test"] = {
        "microsoft": "\r\n".join(key + ": " + value for key, value in fixture["provenance"].items())}
    for name, row in rows.items():
        result = ET.SubElement(results, "{" + NS + "}UnitTestResult", testName=name, outcome="Passed")
        output = ET.SubElement(result, "{" + NS + "}Output")
        stdout = ET.SubElement(output, "{" + NS + "}StdOut")
        marker = "System.DirectoryServices.AccountManagement: " if extract.PRINCIPAL in name else "Microsoft: "
        stdout.text = row["microsoft"] if "FixtureRegistrationTests" in name else marker + row["microsoft"] + ("; AdForLinux: UNTRUSTED" if extract.GROUP_CONSTRUCTOR in name else "\r\nAdForLinux: UNTRUSTED")
    return root


def results(root):
    return list(root.find("{" + NS + "}Results"))


def stdout(result):
    return result.find("{" + NS + "}Output/{" + NS + "}StdOut")


class ExtractionTests(unittest.TestCase):
    def parse(self, root):
        return extract.extract_member(ET.tostring(root), "net8.0")

    def test_exact_case_set(self):
        self.assertEqual(42, len(extract.case_names()))
        self.assertEqual(extract.case_names(), set(self.parse(example())["cases"]))

    def test_clone_output_is_not_an_oracle(self):
        root = example()
        expected = self.parse(root)
        for row in results(root)[:-1]:
            stdout(row).text = stdout(row).text.replace("UNTRUSTED", "anything at all")
        self.assertEqual(expected, self.parse(root))

    def test_literal_escaped_newlines_match_actual_newlines(self):
        root = example()
        expected = self.parse(root)
        for row in results(root):
            stdout(row).text = stdout(row).text.replace("\r\n", "\\r\\n")
        self.assertEqual(expected, self.parse(root))

    def test_changed_microsoft_value_is_retained_not_repaired(self):
        root = example()
        target = next(row for row in results(root) if extract.PRINCIPAL in row.get("testName"))
        stdout(target).text = "System.DirectoryServices.AccountManagement: distinct recorded value"
        parsed = self.parse(root)
        self.assertEqual("distinct recorded value", parsed["cases"][target.get("testName")]["microsoft"])

    def test_missing_case_refused(self):
        root = example()
        root[0].remove(results(root)[0])
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.parse(root)

    def test_duplicate_case_refused(self):
        root = example()
        root[0].append(copy.deepcopy(results(root)[0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.parse(root)

    def test_unexpected_selected_case_refused(self):
        root = example()
        results(root)[0].set("testName", extract.PREFIX + extract.PRINCIPAL + ".new_case()")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            self.parse(root)

    def test_nonpassing_case_refused(self):
        for outcome in ("Failed", "NotExecuted", "Inconclusive"):
            root = example()
            results(root)[0].set("outcome", outcome)
            with self.assertRaisesRegex(ValueError, "Non-passing"):
                self.parse(root)

    def test_clone_only_output_refused(self):
        root = example()
        stdout(results(root)[0]).text = "AdForLinux: accepted"
        with self.assertRaisesRegex(ValueError, "Missing or ambiguous"):
            self.parse(root)

    def test_multiple_microsoft_lines_refused(self):
        root = example()
        target = next(row for row in results(root) if extract.PRINCIPAL in row.get("testName"))
        stdout(target).text += "\r\nSystem.DirectoryServices.AccountManagement: other"
        with self.assertRaisesRegex(ValueError, "Missing or ambiguous"):
            self.parse(root)

    def test_wrong_commit_or_platform_or_target_refused(self):
        for old, new in ((extract.BASE, "wrong"), ("Microsoft Windows", "Linux"), ("Version=v8.0", "Version=v10.0"), ("9.0.0+", "10.0.0+")):
            root = example()
            stdout(results(root)[-1]).text = stdout(results(root)[-1]).text.replace(old, new)
            with self.assertRaises(ValueError):
                self.parse(root)

    def test_ambiguous_paired_constructor_output_refused(self):
        root = example()
        target = next(row for row in results(root) if extract.GROUP_CONSTRUCTOR in row.get("testName"))
        stdout(target).text += "; AdForLinux: duplicate side"
        with self.assertRaisesRegex(ValueError, "Ambiguous legacy"):
            self.parse(root)

    def test_structured_record_must_agree_with_legacy_microsoft_value(self):
        root = example()
        target = next(row for row in results(root) if extract.PRINCIPAL in row.get("testName"))
        row = StructuredTests().row()
        row["caseId"] = target.get("testName")
        row["microsoft"] = "different value"
        stdout(target).text += "\r\n" + structured.PREFIX + json.dumps(row)
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.parse(root)

    def test_consistent_structured_and_legacy_record_accepted(self):
        root = example()
        expected = self.parse(root)
        target = next(row for row in results(root) if extract.PRINCIPAL in row.get("testName"))
        row = StructuredTests().row()
        row["caseId"] = target.get("testName")
        row["microsoft"] = expected["cases"][target.get("testName")]["microsoft"]
        stdout(target).text += "\r\n" + structured.PREFIX + json.dumps(row)
        self.assertEqual(expected, self.parse(root))

    def test_escaped_trx_boundary_does_not_bypass_structured_consistency(self):
        root = example()
        target = next(row for row in results(root) if extract.PRINCIPAL in row.get("testName"))
        row = StructuredTests().row()
        row["caseId"] = target.get("testName")
        row["microsoft"] = "conflicting structured value"
        stdout(target).text += "\r\n" + structured.PREFIX + json.dumps(row)
        for result in results(root):
            stdout(result).text = stdout(result).text.replace("\r\n", "\\r\\n")
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.parse(root)

    def test_missing_header_refused(self):
        root = example()
        root[0].remove(results(root)[-1])
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.parse(root)


class StructuredTests(unittest.TestCase):
    def row(self):
        header = json.loads((run.HERE / "results/run202-net8.0.json").read_text())["provenance"]
        return {"schemaVersion": 1, "caseId": "case", "source": "microsoft-windows-differential",
                "microsoft": {"exceptionType": None, "value": "staged-value"}, "adForLinux": "not an oracle",
                "provenance": {"os": header["OS"], "architecture": "X64", "runtime": ".NET 8.0.31",
                               "target": ".NETCoreApp,Version=v8.0", "sdk": header["SDK"], "commit": extract.BASE,
                               "microsoftDirectoryServices": header["Microsoft DirectoryServices"],
                               "microsoftAccountManagement": header["Microsoft AccountManagement"]}}

    def read(self, row, suffix=""):
        return structured.read(structured.PREFIX + json.dumps(row) + suffix, "case", "net8.0", extract.BASE)

    def test_typed_observation_roundtrip_without_clone_expectations(self):
        row = self.row()
        observation = self.read(row)
        self.assertEqual(row["microsoft"], observation["microsoft"])
        row["adForLinux"] = {"anything": [1, None, False]}
        self.assertEqual(observation, self.read(row))
        self.assertNotIn("adForLinux", observation)

    def test_escaped_text_does_not_split_record(self):
        row = self.row()
        row["microsoft"] = "line one\r\nline two; AdForLinux: remains Microsoft text"
        self.assertEqual(row["microsoft"], self.read(row)["microsoft"])

    def test_escaped_trx_separators_do_not_hide_record_after_human_output(self):
        row = self.row()
        expected = self.read(row)
        # Keep payload escapes intact, including genuine CRLF data inside JSON.
        row["microsoft"] = "line one\r\nline two"
        for separator in ("\r\n", "\\r\\n"):
            stdout = "Microsoft: human output" + separator + structured.PREFIX + json.dumps(row) + separator + "AdForLinux: diagnostics"
            actual = structured.read(stdout, "case", "net8.0", extract.BASE)
            self.assertEqual(row["microsoft"], actual["microsoft"])
            self.assertEqual(expected["provenance"], actual["provenance"])

    def test_duplicate_record_after_escaped_trx_separator_refused(self):
        row = self.row()
        text = structured.PREFIX + json.dumps(row)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            structured.read(text + "\\r\\n" + text, "case", "net8.0", extract.BASE)

    def test_trailing_content_is_not_silently_ignored(self):
        with self.assertRaisesRegex(ValueError, "Trailing"):
            self.read(self.row(), " unexpected")

    def test_duplicate_structured_line_refused(self):
        row = self.row()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.read(row, "\n" + structured.PREFIX + json.dumps(row))

    def test_wrong_schema_identity_platform_commit_or_target_refused(self):
        for key, value in (("schemaVersion", 2), ("caseId", "other"), ("source", "portable")):
            row = self.row()
            row[key] = value
            with self.assertRaises(ValueError):
                self.read(row)
        for key, value in (("commit", "other"), ("os", "Linux"), ("target", ".NETCoreApp,Version=v10.0"),
                           ("microsoftDirectoryServices", "10.0.0"), ("sdk", None)):
            row = self.row()
            row["provenance"][key] = value
            with self.assertRaises(ValueError):
                self.read(row)

    def test_missing_microsoft_is_not_filled_from_clone(self):
        row = self.row()
        del row["microsoft"]
        with self.assertRaisesRegex(ValueError, "Missing or invalid"):
            self.read(row)

    def test_unknown_line_version_refused(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            structured.read("ADFL_DIFFERENTIAL_OBSERVATION_V2: {}", "case", "net8.0", extract.BASE)

    def test_invalid_structure_and_null_metadata_refused(self):
        with self.assertRaises(ValueError):
            self.read([])
        for key in ("os", "microsoftDirectoryServices", "microsoftAccountManagement", "runtime", "architecture"):
            row = self.row()
            row["provenance"][key] = None
            with self.assertRaises(ValueError):
                self.read(row)

    def test_legacy_line_has_no_structured_observation(self):
        self.assertIsNone(structured.read("Microsoft: old format", "case", "net8.0", extract.BASE))


class RunnerTests(unittest.TestCase):
    def test_manifest_and_source_hashes(self):
        run.verify()

    def test_tampered_fixture_refused(self):
        original = Path.read_bytes
        def changed(path):
            raw = original(path)
            return raw + b" " if path.name == "run202-net8.0.json" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                run.verify()

    def test_tampered_linked_source_refused(self):
        original = Path.read_bytes
        def changed(path):
            raw = original(path)
            return raw + b" " if path.name == extract.PRINCIPAL + ".cs" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "source changed"):
                run.verify()

    def test_guard_set_in_child_only_and_no_stale_build(self):
        before = os.environ.get("ADFL_OFFLINE_TESTS")
        for framework in ("net8.0", "net10.0"):
            command, environment = run.prepare(framework)
            self.assertEqual("1", environment["ADFL_OFFLINE_TESTS"])
            self.assertNotIn("--no-build", command)
            self.assertIn("--no-restore", command)
        self.assertEqual(before, os.environ.get("ADFL_OFFLINE_TESTS"))

    def execution(self, root):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replay.trx"
            path.write_bytes(ET.tostring(root))
            return run.verify_execution(path)

    def test_execution_requires_exact_passed_cases(self):
        root = example()
        root[0].remove(results(root)[-1])  # The replay does not run fixture registration.
        self.execution(root)

    def test_zero_execution_refused(self):
        root = example()
        root[0].clear()
        with self.assertRaisesRegex(ValueError, "exactly all 42"):
            self.execution(root)

    def test_failed_execution_refused(self):
        root = example()
        root[0].remove(results(root)[-1])
        results(root)[0].set("outcome", "Failed")
        with self.assertRaisesRegex(ValueError, "non-passing"):
            self.execution(root)

    def test_duplicate_replacing_missing_execution_refused(self):
        root = example()
        root[0].remove(results(root)[-1])
        results(root)[1].set("testName", results(root)[0].get("testName"))
        with self.assertRaisesRegex(ValueError, "exactly all 42"):
            self.execution(root)

    def test_unknown_runtime_refused(self):
        with self.assertRaises(ValueError):
            run.prepare("net9.0")

    def test_project_links_only_reviewed_sources_without_microsoft_package(self):
        project = ET.parse(run.HERE / "AdForLinux.DifferentialTests.csproj")
        linked = [row.get("Include") for row in project.findall(".//Compile")]
        self.assertEqual(["../AdForLinux.DifferentialTests/" + Path(source).name for source in extract.SOURCES] + ["RecordedMicrosoftOracle.cs"], linked)
        self.assertFalse(any("*" in path for path in linked))
        self.assertFalse(any("System.DirectoryServices" in row.get("Include", "") for row in project.findall(".//PackageReference")))
        self.assertEqual("false", project.findtext(".//EnableDefaultCompileItems"))
        self.assertEqual("net8.0;net10.0", project.findtext(".//TargetFrameworks"))


if __name__ == "__main__":
    unittest.main()
