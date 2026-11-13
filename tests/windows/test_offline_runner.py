"""Runner guard tests. Every subprocess invocation is mocked; no testhost/network."""
import importlib.util
from pathlib import Path
import unittest
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("offline_runner", Path(__file__).with_name("run-offline-tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OfflineRunnerTests(unittest.TestCase):
    def test_accidental_live_class_rejected_before_starting_dotnet(self):
        with patch.object(runner.subprocess, "run") as process:
            with self.assertRaises(ValueError):
                runner.run("functional", "net8.0", ["V1PrincipalAuditTests", "CollectionCompatibilityTests", "DirectoryEntryReadTests"])
            process.assert_not_called()

    def test_live_fixture_consumer_rejected_before_starting_dotnet(self):
        with patch.object(runner.subprocess, "run") as process:
            with self.assertRaises(ValueError):
                runner.run("surface", "net8.0", ["UserPrincipalComparisonTests"])
            process.assert_not_called()

    def test_partial_names_raw_filters_and_empty_selection_are_rejected(self):
        for classes in (["V1"], ["V1PrincipalAuditTests|FullyQualifiedName~DirectoryEntryReadTests"], [], ["*"]):
            with self.subTest(classes=classes), patch.object(runner.subprocess, "run") as process:
                with self.assertRaises(ValueError):
                    runner.run("functional", "net8.0", classes)
                process.assert_not_called()

    def test_guard_and_exact_class_boundary_are_mandatory(self):
        command, environment = runner.prepare("functional", "net10.0", ["OfflineExecutionGuardTests"])
        self.assertEqual("1", environment["ADFL_OFFLINE_TESTS"])
        self.assertEqual("FullyQualifiedName~AdForLinux.FunctionalTests.OfflineExecutionGuardTests.", command[-1])
        self.assertNotIn("--no-build", command)

    def test_generated_project_paths_exist_after_layout_move(self):
        for group in runner.GROUPS:
            for framework in ('net8.0','net10.0'):
                with self.subTest(group=group,framework=framework):
                    command,_=runner.prepare(group,framework)
                    self.assertTrue((runner.ROOT/command[2]).is_file(),command[2])

    def test_every_group_runs_with_guard(self):
        for group in runner.GROUPS:
            with self.subTest(group=group), patch.object(runner.subprocess, "run") as process:
                process.return_value.returncode = 0
                self.assertEqual(0, runner.run(group, "net8.0"))
                self.assertEqual("1", process.call_args.kwargs["env"]["ADFL_OFFLINE_TESTS"])

    def test_detached_controls_use_existing_reviewed_class_on_both_frameworks(self):
        for framework in ("net8.0", "net10.0"):
            with self.subTest(framework=framework):
                command, environment = runner.prepare(
                    "surface", framework, ["SearcherValidationContractComparisonTests"])
                self.assertEqual(framework + "-windows", command[command.index("--framework") + 1])
                self.assertEqual(
                    "FullyQualifiedName~AdForLinux.DifferentialTests.SearcherValidationContractComparisonTests.",
                    command[command.index("--filter") + 1])
                self.assertEqual("1", environment["ADFL_OFFLINE_TESTS"])

    def test_reviewed_class_suffix_and_namespace_injection_are_rejected(self):
        for name in ("SearcherValidationContractComparisonTestsSuffix",
                     "SearcherValidationContractComparisonTests.DetachedControls",
                     "AdForLinux.DifferentialTests.SearcherValidationContractComparisonTests"):
            with self.subTest(name=name), patch.object(runner.subprocess, "run") as process:
                with self.assertRaises(ValueError):
                    runner.run("surface", "net8.0", [name])
                process.assert_not_called()

    def test_detached_streaming_collections_are_opt_in_guarded_and_build_current_sources(self):
        for framework in ("net8.0", "net10.0"):
            with self.subTest(framework=framework):
                command, environment = runner.prepare(
                    "functional", framework, ["StreamingSearchResultTests"])
                self.assertEqual(framework, command[command.index("--framework") + 1])
                self.assertEqual(
                    "FullyQualifiedName~AdForLinux.FunctionalTests.StreamingSearchResultTests.",
                    command[command.index("--filter") + 1])
                self.assertEqual("1", environment["ADFL_OFFLINE_TESTS"])
                self.assertNotIn("--no-build", command)
                default_command, _ = runner.prepare("functional", framework)
                self.assertNotIn("StreamingSearchResultTests",
                                 default_command[default_command.index("--filter") + 1])

    def test_detached_streaming_selection_cannot_broaden_to_live_or_similar_classes(self):
        for classes in (["StreamingSearchResultTestsSuffix"],
                        ["StreamingSearchResultTests.Method"],
                        ["AdForLinux.FunctionalTests.StreamingSearchResultTests"],
                        ["StreamingSearchResultTests|FullyQualifiedName~DirectoryEntryReadTests"],
                        ["StreamingSearchResultTests", "DirectoryEntryReadTests"]):
            with self.subTest(classes=classes), patch.object(runner.subprocess, "run") as process:
                with self.assertRaises(ValueError):
                    runner.run("functional", "net8.0", classes)
                process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
