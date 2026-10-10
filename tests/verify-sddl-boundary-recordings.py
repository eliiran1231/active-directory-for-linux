"""Compare actual native batch rows with pinned native evidence, without normalization."""
import gzip
import json
from pathlib import Path
import sys

actual_directory, baseline_path = map(Path, sys.argv[1:])
with gzip.open(baseline_path, 'rt', encoding='utf-8') as source:
    expected = json.load(source)['Observations']
actual = []
for path in sorted(actual_directory.glob('boundary-*.jsonl')):
    batch = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines()]
    header, rows = batch[0], batch[1:]
    assert header['Kind'] == 'Header' and header['TotalCases'] == len(expected), path
    assert len(rows) == header['Count'], path
    assert [r['Case'] for r in rows] == list(range(header['Start'], header['Start'] + header['Count'])), path
    actual.extend(rows)
assert len(actual) == len(expected), (len(actual), len(expected))
for index, (observed, recorded) in enumerate(zip(actual, expected)):
    assert observed['Case'] == recorded['Case'] == index, index
    assert observed == recorded, f'Fresh native boundary mismatch: {index}, {recorded["Label"]}'
print(f'Verified {len(actual)} fresh native observations against {baseline_path.name}; portable gaps remain separately documented.')
