"""Partition/admission tests: never execute dotnet, containers or directory access."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("samba_runner", Path(__file__).with_name("run-samba-tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SambaRunnerTests(unittest.TestCase):
    def test_partition_is_exact_and_preserves_live_pool_tests(self):
        for framework in ("net8.0", "net10.0"):
            steps = runner.prepare(framework, {})
            positive = steps[1][0][-1].split("|")
            negative = steps[2][0][-1].split("&")
            self.assertEqual([item.replace("~", "!~", 1) for item in positive], negative)
            self.assertTrue(all(item.endswith(".") for item in positive))
            self.assertFalse(any("ConnectionPoolSambaTests" in item for item in negative))
            self.assertTrue(any("ConnectionPoolOperationTests." in item for item in positive))
            self.assertTrue(any("CollectionCompatibilityTests." in item for item in positive))
            self.assertEqual("1", steps[1][1]["ADFL_OFFLINE_TESTS"])
            self.assertNotIn("ADFL_OFFLINE_TESTS", steps[2][1])

    def test_guarded_parent_is_never_downgraded(self):
        for value in ("1", "0", "false"):
            with self.assertRaises(ValueError):
                runner.prepare("net8.0", {"ADFL_OFFLINE_TESTS": value})

    def test_offline_failure_stops_before_live_process(self):
        with patch.dict(runner.os.environ, {}, clear=True), patch.object(runner.subprocess, "run") as process:
            process.side_effect = [type("Result", (), {"returncode": code})() for code in (0, 1)]
            self.assertEqual(1, runner.run("net8.0"))
            self.assertEqual(2, process.call_count)
            self.assertEqual("1", process.call_args.kwargs["env"]["ADFL_OFFLINE_TESTS"])


if __name__ == "__main__":
    unittest.main()
