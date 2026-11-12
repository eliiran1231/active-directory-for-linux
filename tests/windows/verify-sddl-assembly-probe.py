#!/usr/bin/env python3
"""Exact native probe freshness, never portable-parity or an allocation formula."""
import gzip
import json
from pathlib import Path
import sys

folder, baseline = map(Path, sys.argv[1:])
expected = [json.loads(line) for line in gzip.decompress(baseline.read_bytes()).decode().splitlines()]
if len(expected) != 56:
    raise SystemExit('Expected fourteen complete four-row native witnesses')
files = {p.name: p for p in folder.glob('witness-*.jsonl')}
if set(files) != {f'witness-{i}.jsonl' for i in range(14)}:
    raise SystemExit('Missing or additional native witness files')
actual = []
for i in range(14):
    rows = [json.loads(line) for line in files[f'witness-{i}.jsonl'].read_text(encoding='utf-8-sig').splitlines()]
    if len(rows) != 4 or [r['Kind'] for r in rows] != ['Attempt', 'Native', 'Compile', 'Replay'] or any(r['Case'] != i for r in rows):
        raise SystemExit(f'Incomplete witness {i}')
    actual.extend(rows)
for index, (left, right) in enumerate(zip(expected, actual)):
    # Preserve original environment fields in recordings; only environment is
    # excluded from exact execution equality. All buffers/errors/counts remain.
    if left['Kind'] == 'Attempt':
        left = {k: v for k, v in left.items() if k not in ('Runtime', 'OS')}
        right = {k: v for k, v in right.items() if k not in ('Runtime', 'OS')}
    if left != right:
        raise SystemExit(f'Native witness {index // 4}, {left["Kind"]} changed; inspect complete artifact, do not normalize outcomes')
print('Verified 14 exact native assembly/capacity witnesses (56 rows); no portable parity or general allocation-model claim.')
