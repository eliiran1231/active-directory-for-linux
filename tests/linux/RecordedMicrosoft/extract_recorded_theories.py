"""Verify the original eight theory multisets from reviewed public Microsoft reads.

Dictionary encoding preserves public counter/site/execution identities. Int64
values are decimal strings to preserve every bit across JSON consumers. There
are no clone values, guessed row identities or inferred opaque observations.
"""
import collections
import hashlib
import json
import pathlib
import re
from extract_offline_oracle import COMMIT, SOURCE, EXCEPTIONS

ROOT=pathlib.Path(__file__).parent
SPECS=json.loads((ROOT/'theory-source-spec.json').read_text())
FRAMEWORKS=['net8.0-windows','net10.0-windows']
TYPES=['null','boolean','int32','int64','exception-type']


def sha(value): return hashlib.sha256(value.encode()).hexdigest()


def index(value, table):
    if type(value) is not int or not 0<=value<len(table):
        raise ValueError('Invalid dictionary index')
    return table[value]


def table(value, width):
    if (type(value) is not list or not value or any(type(item) is not str or len(item)!=width
            or any(c not in '0123456789abcdef' for c in item) for item in value)
            or value!=sorted(set(value))):
        raise ValueError('Invalid/canonical identity table')
    return value


def extract(data, sources=None):
    fields={'schemaVersion','sourceCommit','runId','jobId','projection','recordKind','int64Encoding',
            'frameworks','methods','sites','executions','types','groups'}
    if type(data) is not dict or set(data)!=fields: raise ValueError('Unexpected projection fields')
    for key,value in [('schemaVersion',1),('runId',43105205156),('jobId',130806631589)]:
        if type(data[key]) is not int or data[key]!=value: raise ValueError('Unexpected provenance')
    if (data['sourceCommit']!=COMMIT or data['recordKind']!='reviewed-scalar-pair'
            or data['projection']!='dictionary-encoded-public-Microsoft-expected-scalars'
            or data['int64Encoding']!='canonical-decimal-string'
            or data['frameworks']!=FRAMEWORKS or data['types']!=TYPES):
        raise ValueError('Unexpected provenance or encoding')
    methods=table(data['methods'],64);sites=table(data['sites'],64);executions=table(data['executions'],32)
    if sources is None: sources={s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}
    lookup={};method_names={}
    for spec in SPECS:
        if (spec['file']!=spec['method'].split('.')[0]+'.cs' or not spec.get('review')
                or hashlib.sha256(sources[spec['file']]).hexdigest()!=spec['sha']):
            raise ValueError('Reviewed theory source changed')
        full='AdForLinux.DifferentialTests.'+spec['method'];method=sha(full)
        if method in method_names: raise ValueError('Duplicate reviewed theory method')
        method_names[method]=spec['method']
        for line,member,kinds in spec['sites']:
            site=sha('\0'.join([full,spec['file'],member or spec['method'].split('.')[1],str(line),'value','explicit-microsoft-comparison']))
            key=method,site
            if key in lookup: raise ValueError('Duplicate reviewed theory site')
            lookup[key]=kinds.split('|')
    if set(methods)!=set(method_names) or set(sites)!={site for _,site in lookup}:
        raise ValueError('Unreviewed method/site identity table')
    if type(data['groups']) is not list or not data['groups']: raise ValueError('Missing theory groups')
    captured=collections.defaultdict(dict);seen=set();used_executions=set();owners={};previous=None
    for group in data['groups']:
        if type(group) is not list or len(group)!=4: raise ValueError('Invalid theory group')
        f,m,e,observations=group
        framework=index(f,FRAMEWORKS);method=index(m,methods);execution=index(e,executions)
        head=f,m,e
        if previous is not None and head<=previous: raise ValueError('Duplicate/unordered theory group')
        previous=head;used_executions.add(execution)
        owner=framework,execution
        if owner in owners: raise ValueError("Execution reused across theory methods")
        owners[owner]=method
        if type(observations) is not list or not observations: raise ValueError('Empty/missing theory sequence')
        tokens=[];last_record=0
        for observation in observations:
            if type(observation) is not list or len(observation)!=4: raise ValueError('Invalid Microsoft-only observation')
            record,site_index,type_index,value=observation
            if type(record) is not int or record<=last_record or (framework,record) in seen:
                raise ValueError('Duplicate/invalid public counter')
            last_record=record;seen.add((framework,record))
            site=index(site_index,sites);kind=index(type_index,TYPES)
            if kind not in lookup.get((method,site),[]): raise ValueError('Unreviewed source site/type')
            if kind=='null':
                if value is not None: raise ValueError('Invalid null')
                token='n'
            elif kind=='boolean':
                if type(value) is not bool: raise ValueError('Invalid boolean')
                token='b1' if value else 'b0'
            elif kind=='int32':
                if type(value) is not int or not -(2**31)<=value<2**31: raise ValueError('Invalid Int32')
                token='i32:'+str(value)
            elif kind=='int64':
                if (type(value) is not str or not re.fullmatch(r'-?(0|[1-9][0-9]*)',value)
                        or str(int(value))!=value or not -(2**63)<=int(value)<2**63):
                    raise ValueError('Invalid canonical Int64')
                token='i64:'+value
            else:
                if type(value) is not str or value not in EXCEPTIONS: raise ValueError('Unreviewed exception identifier')
                token='e:'+value
            tokens.append(token)
        key=framework,method_names[method]
        if execution in captured[key]: raise ValueError('Duplicate execution')
        captured[key][execution]=','.join(tokens)
    if used_executions!=set(executions): raise ValueError('Unused execution identity')
    result={}
    for framework in FRAMEWORKS:
        for spec in SPECS:
            values=list(captured[framework,spec['method']].values())
            if len(values)!=spec['rows'] or sum(len(v.split(',')) for v in values)!=spec['checks']:
                raise ValueError('Missing/extra theory executions or observations')
            result[framework+'|'+spec['method']]=sorted(values)
    return result


def csharp_fixture():
    text=(ROOT/'RecordedTheoryExpectations.g.cs').read_text()
    entries=re.findall(r'\["([^"\n]+)"\]\s*=\s*\[(.*?)\],',text,re.S)
    result={key:sorted(re.findall(r'"([^"\n]*)"',block)) for key,block in entries}
    if len(entries)!=16 or len(result)!=16: raise ValueError('Unexpected generated theory fixture shape')
    return result


if __name__=='__main__':
    expected=extract(json.loads((ROOT/'theory-observations.json').read_text()))
    if expected!=csharp_fixture(): raise ValueError('Public Microsoft theory data differs from generated fixture')
    print('PASS: 8 source-reviewed theory methods, 80 executions and 1369 Microsoft observations per runtime; row identities unresolved.')
