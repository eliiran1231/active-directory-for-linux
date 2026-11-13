"""Admit source-reviewed Microsoft reads, preserving record origin and execution.

Unverified assertion wrappers alone establish no provenance. The pinned sites
below read Microsoft objects or earlier values/errors obtained from them.
Literal/clone-side assertion operands and redacted TimeSpan values are excluded.
Explicit comparison sites need a separate review; mixed origins are joined only
within the same recorded framework/method/execution identity.
"""
import collections
import hashlib
import json
import pathlib
import sys
from extract_offline_oracle import COMMIT, EXCEPTIONS, SOURCE, validate_record_pins, validate_input_projection

ROOT = pathlib.Path(__file__).parent
SPECS = json.loads((ROOT/'reviewed-assertions-spec.json').read_text())
APPROVED_ENUM_DOMAINS = {
    ('CompatibilityExpirationPersistenceComparisonTests.Expiration_Save_conversion_and_fresh_reload_match_microsoft',132):
        {'type':'System.DateTimeKind','values':[0,1,2]},
    ('DirectoryEntryRenameComparisonTests.Rename_parameter_nullability_matches_microsoft',18):
        {'type':'System.Reflection.NullabilityState','values':[0,1,2]},
    ('CompatibilityCachedLogonProjectionComparisonTests.LastLogon_projects_cached_timestamp_presence_like_microsoft',71):
        {'type':'System.DateTimeKind','values':[0,1,2]},
    ('CompatibilityCachedLogonProjectionComparisonTests.LastLogon_reread_observes_underlying_cache_changes_like_microsoft',119):
        {'type':'System.DateTimeKind','values':[0,1,2]},
}

def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()

def extract(rows, sources=None):
    if sources is None:
        sources = {s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}
    sites = {}
    for spec in SPECS:
        if hashlib.sha256(sources[spec['file']]).hexdigest() != spec['sha']:
            raise ValueError('Reviewed source changed')
        if spec.get('kind','Theory') not in ('Fact','Theory') or (spec.get('kind')=='Fact' and spec['rows']!=1):
            raise ValueError('Invalid source method kind or Fact execution count')
        scope=spec.get('coverage','partial')
        if scope not in ('partial','complete-local-metadata-fact'):
            raise ValueError('Unreviewed completion scope')
        if scope=='complete-local-metadata-fact' and (
                spec.get('kind')!='Fact' or spec['rows']!=1 or spec['checks']!=1
                or spec.get('adaptation') or spec.get('inputProjection') or not spec.get('completionReview')):
            raise ValueError('Complete metadata Fact requires explicit single-assertion review')
        validate_record_pins(spec)
        validate_input_projection(spec,sources[spec['file']])
        full = 'AdForLinux.DifferentialTests.'+spec['method']
        if spec.get('explicitSites') and not spec.get('explicitReview'):
            raise ValueError('Mixed-origin sites require an explicit source review')
        reviewed = [(site,'unverified-assertion-operand') for site in spec['sites']]
        reviewed += [(site,'reviewed-scalar-pair') for site in spec.get('explicitSites',[])]
        for site,record_kind in reviewed:
            line,member,types = site[:3]
            explicit=record_kind=='reviewed-scalar-pair'
            role = 'value' if explicit else site[3] if len(site)>3 else 'assert-equal-expected'
            origin = 'explicit-microsoft-comparison' if explicit else 'assertion-operand-unverified'
            key = sha(full), sha('\0'.join([full,spec['file'],member or spec['method'].split('.')[1],str(line),role,origin]))
            if key in sites: raise ValueError('Duplicate reviewed source site')
            sites[key] = spec['method'], line, types.split('|'),record_kind
    groups = collections.defaultdict(lambda:collections.defaultdict(list))
    seen = set()
    occurrence_counts = collections.Counter()
    limits = {s['method']:s.get('maxOccurrences',{}) for s in SPECS}
    record_pins = {s['method']:s.get('reviewedRecords') for s in SPECS}
    enum_domains = {s['method']:s.get('enumDomains',{}) for s in SPECS}
    for row in rows:
        framework = row['framework']
        if framework not in ('net8.0-windows','net10.0-windows') or row['commit'] != COMMIT or row['kind'] not in ('unverified-assertion-operand','reviewed-scalar-pair'):
            raise ValueError('Unexpected provenance')
        key = row['testMethodSha256'],row['sourceSiteSha256']
        if key not in sites: raise ValueError('Unreviewed source site or operand role')
        method,line,types,record_kind = sites[key]
        if row['kind'] != record_kind: raise ValueError('Record kind disagrees with reviewed source origin')
        record = row['record']
        if type(record) is not int or record <= 0 or (framework,record) in seen:
            raise ValueError('Duplicate/invalid public record')
        pins=record_pins[method]
        if pins is not None and record not in pins[framework]:
            raise ValueError('Unreviewed helper invocation record identity')
        seen.add((framework,record))
        execution = row['execution']
        if type(execution) is not str or len(execution) != 32 or any(c not in '0123456789abcdef' for c in execution):
            raise ValueError('Invalid execution')
        operand = row['microsoftExpectedObservation'] if record_kind=='reviewed-scalar-pair' else row['operand']
        kind,value = operand['type'],operand['value']
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
        elif kind == 'int64':
            if type(value) is not int or not -(2**63) <= value < 2**63: raise ValueError('Invalid Int64')
            token = 'i64:'+str(value)
        elif kind == 'enum-int64':
            domain=enum_domains[method].get(str(line))
            if domain is None or domain!=APPROVED_ENUM_DOMAINS.get((method,line)):
                raise ValueError('Unreviewed enum domain')
            if type(value) is not int or not -(2**63)<=value<2**63 or value not in domain['values']:
                raise ValueError('Invalid enum Int64 or domain value')
            token='enum64:'+str(value)
        elif kind == 'exception-type':
            if type(value) is not str or value not in EXCEPTIONS: raise ValueError('Unreviewed exception')
            token = 'e:'+value
        else: raise ValueError('Unreviewed type')
        occurrence = framework,method,execution,line
        occurrence_counts[occurrence] += 1
        maximum = limits[method].get(str(line))
        if maximum is not None and occurrence_counts[occurrence] > maximum:
            raise ValueError('Unreviewed helper invocation: clone-side helper call excluded')
        groups[framework,method][execution].append((record,str(line)+'='+token))
    result = {'schemaVersion':1,'sourceCommit':COMMIT,'runId':43105205156,'jobId':130806631589,
              'coverage':'partial-reviewed-Microsoft-method-multisets',
              'sourceSha256':{s['file']:s['sha'] for s in SPECS},
              'methodKinds':{s['method']:s.get('kind','Theory') for s in SPECS},
              'completeMetadataFacts':sorted(s['method'] for s in SPECS if s.get('coverage')=='complete-local-metadata-fact'),
              'inputProjections':{s['method']:s['inputProjection'] for s in SPECS if s.get('inputProjection')},'frameworks':{}}
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
