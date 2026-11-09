#!/usr/bin/env python3
"""Supervise the opt-in read probe; never create a fixture or write credentials."""
import argparse
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time


def child_environment(parent):
    result = {key: parent[key] for key in (
        "PATH", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO", "XDG_RUNTIME_DIR",
        "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SystemRoot", "WINDIR",
        "ADFL_OFFLINE_TESTS", "ADFL_ACCOUNT_READ_PROBE", "LDAPTLS_REQCERT", "LDAPTLS_REQSAN",
    ) if key in parent}
    result.update(DOTNET_EnableDiagnostics="0", COMPlus_EnableDiagnostics="0",
                  DOTNET_DbgEnableMiniDump="0", COMPlus_DbgEnableMiniDump="0")
    return result


def read_bounded(stream, limit, remaining):
    results = queue.Queue(maxsize=1)
    def read():
        try: results.put(stream.readline(limit + 1))
        except Exception: results.put(None)
    threading.Thread(target=read, daemon=True).start()
    value = results.get(timeout=remaining)
    if value is None or len(value) > limit or not value.endswith(b"\n"):
        raise ValueError()
    return value


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError()
        result[key] = value
    return result


def timed_action(action, remaining):
    results = queue.Queue(maxsize=1)
    def execute():
        try: results.put((True, action()))
        except Exception: results.put((False, None))
    threading.Thread(target=execute, daemon=True).start()
    ok, value = results.get(timeout=remaining)
    if not ok: raise ValueError()
    return value


def run(arguments, environment=None, input_stream=None):
    parent = os.environ if environment is None else environment
    source = sys.stdin if input_stream is None else input_stream
    if parent.get("ADFL_OFFLINE_TESTS"):
        print("BLOCKED offline-guard", file=sys.stderr)
        return 2
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            print("BLOCKED invalid-launcher-configuration", file=sys.stderr)
            raise SystemExit(2)
    parser = Parser(description=__doc__)
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--framework", choices=("net8.0", "net10.0"), required=True)
    options, probe_arguments = parser.parse_known_args(arguments)
    assembly = Path(__file__).resolve().parent / "bin" / "Release" / options.framework / "AccountManagement.ReadProbe.dll"
    if arguments.count("--dotnet") != 1 or arguments.count("--framework") != 1 or not assembly.is_file() or source.isatty():
        print("BLOCKED prerequisites", file=sys.stderr)
        return 2
    started = time.monotonic()
    # Reserve five seconds for bounded kill/reaping within the 60-second wall
    # budget. An independent timer also covers blocked pipe writes and flushes.
    remaining = lambda: max(0.001, 55 - (time.monotonic() - started))
    def disable_core():
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    process = subprocess.Popen([options.dotnet, str(assembly), "--supervised-read", *probe_arguments],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=child_environment(parent), start_new_session=os.name != "nt",
        preexec_fn=disable_core if os.name != "nt" else None)
    def kill():
        try:
            if process.poll() is None:
                if os.name == "nt": process.kill()
                else: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    deadline = threading.Timer(remaining(), kill)
    deadline.daemon = True
    deadline.start()
    try:
        first = timed_action(lambda: process.stdout.readline(129), remaining())
        if not first.startswith(b"READY "):
            process.wait(timeout=remaining())
            if process.returncode == 2:
                print("BLOCKED child-admission", file=sys.stderr)
                return 2
            raise ValueError()
        if len(first) > 128 or not first.endswith(b"\n"): raise ValueError()
        nonce = (first[:-2] if first.endswith(b"\r\n") else first[:-1])[6:].decode("ascii")
        if len(nonce) != 64 or any(value not in "0123456789ABCDEF" for value in nonce): raise ValueError()
        # Child gates pass before the launcher reads any secret. No secret env.
        frame = json.loads(read_bounded(source.buffer, 60000, remaining()), object_pairs_hook=strict_object)
        if set(frame) != {"bindDn", "password"} or not all(isinstance(value, str) and value for value in frame.values()): raise ValueError()
        frame["nonce"] = nonce
        encoded = json.dumps(frame, ensure_ascii=True).encode("ascii") + b"\n"
        if len(encoded) > 65536: raise ValueError()
        def write():
            process.stdin.write(encoded)
            process.stdin.flush()
        timed_action(write, remaining())
        # Keep stdin open while waiting: EOF is the child's parent-death signal.
        process.wait(timeout=remaining())
        stdout = timed_action(lambda: process.stdout.read(256), remaining())
        stderr = timed_action(lambda: process.stderr.read(256), remaining())
        if process.returncode == 0 and stdout in (b"PASS read-only-protocols-entry-accountmanagement\n", b"PASS read-only-protocols-entry-accountmanagement\r\n") and not stderr:
            print("PASS read-only-protocols-entry-accountmanagement")
            return 0
        print("FAIL admitted-read", file=sys.stderr)
        return 1
    except Exception:
        print("FAIL supervision-or-input", file=sys.stderr)
        return 1
    finally:
        deadline.cancel()
        try:
            kill()
            process.wait(timeout=5)
        except Exception:
            print("FAIL cleanup", file=sys.stderr)
            return 1
        for stream in (process.stdin, process.stdout, process.stderr): stream.close()


if __name__ == "__main__": raise SystemExit(run(sys.argv[1:]))
