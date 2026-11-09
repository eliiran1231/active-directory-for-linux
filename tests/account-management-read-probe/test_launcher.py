#!/usr/bin/env python3
"""Supervision tests: mocks plus one local Python child, no LDAP or real secrets."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest import mock

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("read_probe_launcher", Path(__file__).with_name("run-probe.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class Input:
    def __init__(self, value=None): self.value = value; self.reads = 0
    def isatty(self): return False
    @property
    def buffer(self):
        self.reads += 1
        if self.value is None: raise AssertionError("credential input must remain unread")
        return io.BytesIO(self.value)


class Sink(io.BytesIO):
    def close(self): self.saved = self.getvalue(); super().close()


class Process:
    pid = 12345
    def __init__(self, ready=True, crlf=False, timeout=False):
        newline = b"\r\n" if crlf else b"\n"
        self.stdout = io.BytesIO((b"READY " + b"A" * 64 + newline + b"PASS read-only-protocols-entry-accountmanagement" + newline) if ready else b"")
        self.stderr = io.BytesIO(b"" if ready else b"BLOCKED containment-review-pending\n")
        self.stdin = Sink(); self.returncode = None; self.ready = ready; self.timeout = timeout; self.killed = False
    def poll(self): return self.returncode
    def kill(self): self.returncode = -9; self.killed = True
    def wait(self, timeout):
        if self.timeout and not self.killed: raise subprocess.TimeoutExpired("synthetic", timeout)
        if self.returncode is None:
            if self.ready: assert not self.stdin.closed
            self.returncode = 0 if self.ready else 2
        return self.returncode


class LauncherTests(unittest.TestCase):
    arguments = ["--dotnet", "synthetic-dotnet", "--framework", "net8.0", "--allow-live-read"]
    def run_case(self, process, source):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(launcher.subprocess, "Popen", return_value=process) as launch, \
             mock.patch.object(launcher.Path, "is_file", return_value=True), \
             mock.patch.object(launcher.os, "killpg", side_effect=lambda *_: process.kill()), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = launcher.run(self.arguments, environment={}, input_stream=source)
        self.assertEqual(launch.call_count, 1)
        return status, output.getvalue(), errors.getvalue()

    def test_environment_drops_secrets_native_overrides_and_startup_hooks(self):
        source = {"GH_TOKEN": "synthetic", "AD_BIND_PASSWORD": "synthetic", "LD_PRELOAD": "synthetic",
                  "LDAPCONF": "synthetic", "DOTNET_STARTUP_HOOKS": "synthetic", "ADFL_OFFLINE_TESTS": "0",
                  "LDAPTLS_REQCERT": "demand", "LDAPTLS_REQSAN": "demand", "DOTNET_EnableDiagnostics": "1"}
        result = launcher.child_environment(source)
        for key in ("GH_TOKEN", "AD_BIND_PASSWORD", "LD_PRELOAD", "LDAPCONF", "DOTNET_STARTUP_HOOKS"):
            self.assertNotIn(key, result)
        self.assertEqual(result["ADFL_OFFLINE_TESTS"], "0")
        self.assertEqual(result["DOTNET_EnableDiagnostics"], "0")

    def test_guard_prevents_process_launch_and_secret_input(self):
        for guard in ("1", "0", "false"):
            with self.subTest(guard=guard), mock.patch.object(launcher.subprocess, "Popen") as process, contextlib.redirect_stderr(io.StringIO()):
                source = Input()
                self.assertEqual(launcher.run([], environment={"ADFL_OFFLINE_TESTS": guard}, input_stream=source), 2)
                process.assert_not_called(); self.assertEqual(source.reads, 0)

    def test_blocked_child_preserves_blocked_exit_and_never_reads_input(self):
        source = Input()
        status, stdout, stderr = self.run_case(Process(ready=False), source)
        self.assertEqual((status, stdout, stderr, source.reads), (2, "", "BLOCKED child-admission\n", 0))

    def test_success_requires_exact_result_open_supervision_pipe_and_framing(self):
        for crlf in (False, True):
            with self.subTest(crlf=crlf):
                process = Process(crlf=crlf)
                status, stdout, stderr = self.run_case(process, Input(b'{"bindDn":"synthetic-reader","password":"synthetic-value"}\n'))
                self.assertEqual((status, stdout, stderr), (0, "PASS read-only-protocols-entry-accountmanagement\n", ""))
                frame = json.loads(process.stdin.saved)
                self.assertEqual(frame["nonce"], "A" * 64)
                self.assertNotIn("synthetic-value", stdout + stderr)

    def test_duplicate_or_oversized_encoded_frames_fail_without_echo(self):
        for frame in (b'{"bindDn":"a","password":"synthetic","password":"duplicate"}\n',
                      (json.dumps({"bindDn": "a", "password": "\u2603" * 15000}, ensure_ascii=False) + "\n").encode("utf-8")):
            with self.subTest(size=len(frame)):
                process = Process()
                status, stdout, stderr = self.run_case(process, Input(frame))
                self.assertEqual(status, 1); self.assertEqual(stdout, "")
                self.assertEqual(stderr, "FAIL supervision-or-input\n")
                self.assertTrue(process.killed)
                self.assertEqual(process.stdin.saved, b"")

    def test_timeout_kills_and_reaps_scoped_child(self):
        process = Process(timeout=True)
        status, stdout, stderr = self.run_case(process, Input(b'{"bindDn":"synthetic","password":"synthetic"}\n'))
        self.assertEqual((status, stdout, stderr), (1, "", "FAIL supervision-or-input\n"))
        self.assertTrue(process.killed)

    def test_bounded_reads_reject_empty_overlong_and_unterminated_data(self):
        for value in (b"", b"x" * 6 + b"\n", b"abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.read_bounded(io.BytesIO(value), 5, 1)
        self.assertEqual(launcher.read_bounded(io.BytesIO(b"abc\n"), 5, 1), b"abc\n")

    def test_deadline_kills_and_reaps_real_local_protocol_child(self):
        real_popen, real_timer = subprocess.Popen, threading.Timer
        children = []
        def spawn(command, **options):
            self.assertEqual(command[0], "synthetic-dotnet")
            child = real_popen([sys.executable, "-c",
                'import sys,time;print("READY "+"A"*64,flush=True);sys.stdin.buffer.readline();time.sleep(30)'], **options)
            children.append(child)
            return child
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(launcher.subprocess, "Popen", side_effect=spawn), \
             mock.patch.object(launcher.Path, "is_file", return_value=True), \
             mock.patch.object(launcher.threading, "Timer", side_effect=lambda _, action: real_timer(0.5, action)), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = launcher.run(self.arguments, environment={},
                input_stream=Input(b'{"bindDn":"synthetic","password":"synthetic"}\n'))
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "FAIL admitted-read\n")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())


if __name__ == "__main__": unittest.main()
