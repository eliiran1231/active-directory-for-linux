"""Reproduce the original hardcoded values from source-reviewed public operands.

The capture marks these assertion operands unverified. The separate source
review pins their Microsoft origin; wrappers alone never establish origin.
Only partial scalar projections are reproduced, without clone values or row IDs.
"""
import collections
import hashlib
import json
import pathlib
import re
from extract_offline_oracle import COMMIT, SOURCE, EXCEPTIONS

ROOT=pathlib.Path(__file__).parent
SPECS=json.loads((ROOT/'hardcoded-source-spec.json').read_text())
FRAMEWORKS=('net8.0-windows','net10.0-windows')


def sha(text): return hashlib.sha256(text.encode()).hexdigest()


def csharp_fixture():
    entries=re.findall(r'\["([^"\n]+)"\]\s*=\s*\[(.*?)\]',(ROOT/'HardcodedExpectations.g.cs').read_text(),re.S)
    result={name:json.loads('['+re.sub(r'(?<=\d)L\b','',block)+']') for name,block in entries}
    if len(entries)!=26 or len(result)!=26 or set(result)!={s['key'] for s in SPECS}:
        raise ValueError('Unexpected hardcoded fixture shape')
    blocks=dict(entries)
    for spec in SPECS:
        values=result[spec['key']]
        expected_type=bool if spec['type']=='boolean' else str if spec['type']=='exception-type' else int
        if (len(values)!=spec['occurrences'] or any(type(v) is not expected_type for v in values)
                or (spec['type']=='int64')!=bool(re.search(r'(?<=\d)L\b',blocks[spec['key']]))):
            raise ValueError('Changed hardcoded fixture scalar type')
    return result


def extract(data, sources=None):
    if type(data) is not dict or set(data)!={'schemaVersion','sourceCommit','runId','jobId','recordKind','projection','rows'}:
        raise ValueError('Unexpected projection fields')
    for key,value in [('schemaVersion',1),('runId',43105205156),('jobId',130806631589)]:
        if type(data[key]) is not int or data[key]!=value: raise ValueError('Unexpected provenance')
    if (data['sourceCommit']!=COMMIT or data['recordKind']!='unverified-assertion-operand'
            or data['projection']!='source-reviewed-Microsoft-expected-operands'):
        raise ValueError('Unexpected provenance')
    if sources is None: sources={s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}
    sites={};spec_keys=set()
    for spec in SPECS:
        if not spec.get('review') or hashlib.sha256(sources[spec['file']]).hexdigest()!=spec['sha']:
            raise ValueError('Reviewed hardcoded source changed')
        full='AdForLinux.DifferentialTests.'+spec['method']
        key=sha(full),sha('\0'.join([full,spec['file'],spec['member'],str(spec['line']),
            'assert-equal-expected','assertion-operand-unverified']))
        if key!=(spec['methodHash'],spec['siteHash']) or key in sites or spec['key'] in spec_keys:
            raise ValueError('Duplicate or changed reviewed source identity')
        sites[key]=spec;spec_keys.add(spec['key'])
    if type(data['rows']) is not list or not data['rows']: raise ValueError('Missing observations')
    groups=collections.defaultdict(list);seen=set();last={};executions=collections.defaultdict(set);owners={}
    for row in data['rows']:
        if type(row) is not dict or set(row)!={'framework','record','execution','testMethodSha256','sourceSiteSha256','operand'}:
            raise ValueError('Unexpected Microsoft-only record fields')
        framework=row['framework'];record=row['record'];execution=row['execution']
        if type(framework) is not str or framework not in FRAMEWORKS: raise ValueError('Unexpected framework')
        if type(record) is not int or record<=last.get(framework,0) or (framework,record) in seen:
            raise ValueError('Duplicate or unordered public record')
        last[framework]=record;seen.add((framework,record))
        if type(execution) is not str or not re.fullmatch('[0-9a-f]{32}',execution): raise ValueError('Invalid execution identity')
        key=row['testMethodSha256'],row['sourceSiteSha256']
        if key not in sites: raise ValueError('Unreviewed source origin or role')
        spec=sites[key];owner=framework,execution
        if owner in owners and owners[owner]!=spec['method']: raise ValueError('Execution reused across methods')
        owners[owner]=spec['method'];executions[framework,spec['method']].add(execution)
        operand=row['operand']
        if type(operand) is not dict or set(operand)!={'type','value'} or operand['type']!=spec['type']:
            raise ValueError('Unexpected scalar type or payload')
        value=operand['value'];kind=operand['type']
        if kind=='boolean':
            valid=type(value) is bool
        elif kind in ('int32','int64'):
            bits=32 if kind=='int32' else 64
            valid=type(value) is int and -(2**(bits-1))<=value<2**(bits-1)
        elif kind=='exception-type':
            valid=type(value) is str and value in EXCEPTIONS
        else: valid=False
        if not valid: raise ValueError('Invalid reviewed scalar value')
        groups[framework,spec['key']].append(value)
    for framework in FRAMEWORKS:
        for spec in SPECS:
            if len(groups[framework,spec['key']])!=spec['occurrences']:
                raise ValueError('Missing or extra source observations')
            if len(executions[framework,spec['method']])!=1:
                raise ValueError('Fact requires exactly one execution')
    return {framework:{spec['key']:groups[framework,spec['key']] for spec in SPECS} for framework in FRAMEWORKS}


if __name__=='__main__':
    result=extract(json.loads((ROOT/'hardcoded-observations.json').read_text()))
    expected=csharp_fixture()
    if any(values!=expected for values in result.values()): raise ValueError('Microsoft observations differ from hardcoded fixture')
    print('PASS: 26 reviewed source sites reproduce 78 Microsoft scalar observations per runtime; coverage remains partial.')
