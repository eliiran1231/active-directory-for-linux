"""Stream exact native layer evidence; native freshness is not portable parity."""
import gzip
import json
from pathlib import Path
import sys

actual_directory, baseline_path = map(Path, sys.argv[1:])
count = 0
with gzip.open(baseline_path, 'rt', encoding='utf-8') as source:
    for path in sorted(actual_directory.glob('layer-*.jsonl')):
        actual = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines()]
        expected = [json.loads(next(source)) for _ in range(3)]
        assert [row['Kind'] for row in actual] == ['Attempt', 'Native', 'Managed'], path
        assert all(row['Case'] == count for row in actual + expected), path
        # Environment metadata is retained in the baseline, not an outcome.
        for key in ('Runtime', 'OS', 'AclAssembly'):
            actual[0].pop(key)
            expected[0].pop(key)
        assert actual == expected, f'Native layer mismatch: {count}, {expected[0]["Label"]}'
        count += 1
    assert source.readline() == '', 'Missing native layer cases'
assert count > 0, 'No native layer cases'
print(f'Verified {count} exact native conversion/managed-construction observations; this is not portable parity.')
