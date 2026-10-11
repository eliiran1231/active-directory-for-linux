#!/usr/bin/env python3
"""Exact freshness for one six-case experiment; not a general sizing formula."""
import gzip
import json
from pathlib import Path
import sys

folder, baseline = map(Path, sys.argv[1:])
expected = [json.loads(line) for line in gzip.decompress(baseline.read_bytes()).decode().splitlines()]
if len(expected) != 24:
    raise SystemExit('Expected six complete four-row token-partition witnesses')
files = {p.name: p for p in folder.glob('witness-*.jsonl')}
if set(files) != {f'witness-{i}.jsonl' for i in range(6)}:
    raise SystemExit('Missing or additional token-partition witness files')
actual = []
for i in range(6):
    rows = [json.loads(line) for line in files[f'witness-{i}.jsonl'].read_text(encoding='utf-8-sig').splitlines()]
    if len(rows) != 4 or [r['Kind'] for r in rows] != ['Attempt', 'CompileControl', 'Native', 'Replay'] or any(r['Case'] != i for r in rows):
        raise SystemExit(f'Incomplete token-partition witness {i}')
    actual.extend(rows)
for index, (left, right) in enumerate(zip(expected, actual)):
    # Keep environment in recordings. All errors, token widths and buffer bytes
    # remain part of freshness equality; unsuccessful controls stay inconclusive.
    if left['Kind'] == 'Attempt':
        left = {k: v for k, v in left.items() if k not in ('Runtime', 'OS')}
        right = {k: v for k, v in right.items() if k not in ('Runtime', 'OS')}
    if left != right:
        raise SystemExit(f'Token-partition witness {index // 4}, {left["Kind"]} changed; inspect the complete artifact')
print('Verified 6 exact token-partition witnesses (24 rows); no general allocation-model claim.')
