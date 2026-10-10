#!/usr/bin/env python3
"""Opt-in Linux local invariant workers. No restore, native Windows work, or network setup."""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument('--dotnet', required=True)
parser.add_argument('--framework', choices=['net8.0', 'net10.0'], required=True)
parser.add_argument('--results', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
args.results.mkdir(parents=True, exist_ok=True)
args.results = args.results.resolve()
if any(args.results.iterdir()):
    parser.error('--results must be empty so earlier failure evidence is preserved')
methods = [
    'Recorded_raw_mutations_roundtrip_or_refuse_without_changing_buffers',
    'Recorded_text_mutations_preserve_successful_binary_and_failed_exports',
    'Conditional_payload_mutations_never_silently_lose_bytes',
    'Generated_edit_back_keeps_snapshots_and_rolls_back_every_failed_publication',
    'Deep_and_malformed_expressions_stay_inside_local_allocation_budget',
]

def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # A global 64 MiB file-size cap aborts this .NET 8 host during startup with
    # exit 153, before tests execute. Bound evidence output below instead.
    os.nice(5)

env = os.environ.copy()
env.update(ADFL_BOUNDED_INVARIANT_WORKER='1', DOTNET_GCHeapHardLimit='0x10000000',
           DOTNET_GCConserveMemory='9', DOTNET_PROCESSOR_COUNT='2')
summary = []
for index, method in enumerate(methods):
    stem = f'invariant-{args.framework}-{index}'
    command = [args.dotnet, 'test', 'tests/AdForLinux.FunctionalTests/AdForLinux.FunctionalTests.csproj',
               '-c', 'Release', '-f', args.framework, '--no-build', '--no-restore',
               '--filter', f'FullyQualifiedName~SddlInvariantProbeTests.{method}',
               '--diag', str(args.results / f'{stem}-diag.log'),
               '--logger', f'trx;LogFileName={stem}.trx', '--results-directory', str(args.results)]
    started = time.monotonic()
    with (args.results / f'{stem}.log').open('w') as log:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True, preexec_fn=limits)
        timed_out = False
        output_limited = False
        while True:
            try:
                code = process.wait(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                timed_out = time.monotonic() - started >= 60
                output_limited = sum(p.stat().st_size for p in args.results.glob(f'{stem}*') if p.is_file()) > 64 * 1024**2
                if timed_out or output_limited:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
                    break
    # dotnet test can exit successfully when a filter matches no tests. Require an
    # actual single passing worker, including when the opt-in flag is misconfigured.
    passed = False
    try:
        results = ET.parse(args.results / f'{stem}.trx').findall('.//{*}UnitTestResult')
        passed = len(results) == 1 and results[0].get('outcome') == 'Passed'
    except (OSError, ET.ParseError):
        pass
    item = dict(method=method, exitCode=code, workerPassed=passed,
                wallSeconds=round(time.monotonic()-started, 3), timedOut=timed_out, outputLimited=output_limited)
    summary.append(item)
    print(json.dumps(item), flush=True)
    # Stop at an invariant/process failure; retain evidence before any rerun/fix.
    if code != 0 or not passed:
        break
(args.results / f'invariant-{args.framework}-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
raise SystemExit(0 if len(summary) == len(methods) and all(x['exitCode'] == 0 and x['workerPassed'] for x in summary) else 1)
