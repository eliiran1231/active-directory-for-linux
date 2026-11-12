"""Admit Microsoft reads reviewed in reviewed-assertions-spec.json.

Unverified assertion wrappers alone establish no provenance. The pinned sites
below read Microsoft objects or earlier values/errors obtained from them.
Literal/clone-side assertion operands and redacted TimeSpan values are excluded.
"""
import collections
import hashlib
import json
import pathlib
import sys
from extract_offline_oracle import COMMIT, EXCEPTIONS, SOURCE

ROOT = pathlib.Path(__file__).parent
SPECS = json.loads((ROOT/'reviewed-assertions-spec.json').read_text())

def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()

def extract(rows, sources=None):
    if sources is None:
        sources = {s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}
    sites = {}
    for spec in SPECS:
        if hashlib.sha256(sources[spec['file']]).hexdigest() != spec['sha']:
            raise ValueError('Reviewed source changed')
        full = 'AdForLinux.DifferentialTests.'+spec['method']
        for line,member,types in spec['sites']:
            key = sha(full), sha('\0'.join([full,spec['file'],member or spec['method'].split('.')[1],str(line),'assert-equal-expected','assertion-operand-unverified']))
            sites[key] = spec['method'], line, types.split('|')
    groups = collections.defaultdict(lambda:collections.defaultdict(list))
    seen = set()
    for row in rows:
        framework = row['framework']
        if framework not in ('net8.0-windows','net10.0-windows') or row['commit'] != COMMIT or row['kind'] != 'unverified-assertion-operand':
            raise ValueError('Unexpected provenance')
        key = row['testMethodSha256'],row['sourceSiteSha256']
        if key not in sites: raise ValueError('Unreviewed source site or operand role')
        method,line,types = sites[key]
        record = row['record']
        if type(record) is not int or record <= 0 or (framework,record) in seen:
            raise ValueError('Duplicate/invalid public record')
        seen.add((framework,record))
        execution = row['execution']
        if type(execution) is not str or len(execution) != 32 or any(c not in '0123456789abcdef' for c in execution):
            raise ValueError('Invalid execution')
        kind,value = row['operand']['type'],row['operand']['value']
        if kind not in types: raise ValueError('Unexpected scalar type')
        if kind == 'null':
            if value is not None: raise ValueError('Invalid null')
            token = 'n'
        elif kind == 'boolean':
            if type(value) is not bool: raise ValueError('Invalid boolean')
            token = 'b1' if value else 'b0'
        elif kind == 'int32':
            if type(value) is not int or not -(2**31) <= value < 2**31: raise ValueError('Invalid Int32')
            token = 'i32:'+str(value)
        elif kind == 'exception-type':
            if type(value) is not str or value not in EXCEPTIONS: raise ValueError('Unreviewed exception')
            token = 'e:'+value
        else: raise ValueError('Unreviewed type')
        groups[framework,method][execution].append((record,str(line)+'='+token))
    result = {'schemaVersion':1,'sourceCommit':COMMIT,'runId':43105205156,'jobId':130806631589,
              'coverage':'partial-reviewed-Microsoft-assertion-method-multisets',
              'sourceSha256':{s['file']:s['sha'] for s in SPECS},'frameworks':{}}
    for framework in ('net8.0-windows','net10.0-windows'):
        methods = {}
        for spec in SPECS:
            captured = groups[framework,spec['method']]
            if len(captured) != spec['rows'] or sum(map(len,captured.values())) != spec['checks']:
                raise ValueError('Missing/extra executions or observations: '+spec['method'])
            methods[spec['method']] = sorted(','.join(token for _,token in sorted(values)) for values in captured.values())
        result['frameworks'][framework] = methods
    return result

if __name__ == '__main__':
    rows = [json.loads(line) for line in (ROOT/'reviewed-assertions.jsonl').read_text().splitlines()]
    output = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'reviewed-assertions-oracle.json'
    output.write_text(json.dumps(extract(rows),indent=2)+'\n')
