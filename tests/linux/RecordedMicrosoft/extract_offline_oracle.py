"""Source-reviewed admission for partial offline projections from the public job log.

Only Microsoft operands at the explicit Comparison.Check sites below are admitted.
No execution GUID is assigned to a theory input: output is a method multiset.
"""
import collections
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).parent
SOURCE = ROOT.parents[1] / 'windows/AdForLinux.DifferentialTests'
COMMIT = '93f1f9c6b593d9f4dd38d23616632dc6a015f4ca'
# method: (source hash, execution count, scalar count, source member, admitted lines/types)
METHODS = {
 'CompatibilityContextValidationComparisonTests.Full_constructor_local_validation_precedence_matches_microsoft':
 ('77b3d08e9b92924ec610a6b3da21fb3e056eb544c4087acce2433fbcf6118678', 16, 27, None, {58:'exception-type',59:'null'}),
 'CompatibilityContextlessSearcherComparisonTests.Rejected_contextless_filter_assignment_and_followup_match_microsoft':
 ('f4b9f9dba7cca739025a313dbd321f0066278b41c1c591df728da9525c5207fa', 8, 24, None, {65:'boolean',66:'boolean',108:'null'}),
 'AdvancedFilterInstanceComparisonTests.Built_in_criteria_can_be_configured_without_an_owner':
 ('5f07ee5168fb722384258b4df99049c5be16803164865cbbc419bf7a2b79242f', 12, 48, 'CompareError', {77:'null',78:'null'}),
 'AdvancedFiltersOwnerComparisonTests.Protected_constructor_accepts_the_same_owner_values':
 ('d34420effe683b3935634d4455b3a497af89dc808d4a80160fe0ea526915d6e2', 2, 4, None, {23:'null',24:'null'}),
 'CompatibilityDisposedEntryValidationComparisonTests.Disposed_entry_and_invalid_argument_precedence_match_microsoft':
 ('86d49aeeb6e76da9b02b1531978169acb854949dec75cb54435b063562608db5', 9, 58, None, {44:'exception-type',45:'null',47:'int32',48:'null'}),
 'CompatibilityDisposedPropertyContainsComparisonTests.Disposed_owner_and_null_name_validation_have_matching_precedence':
 ('eeaca65b3658b8b830287d59af77e6994159be4fbea84d9a1544f6898f7b6ed5', 3, 6, None, {37:'exception-type',38:'null',39:'null'}),
 'CompatibilityFailedRefreshWrapperComparisonTests.Failed_refresh_preserves_property_wrapper_like_microsoft':
 ('33ecf919ff512b6f7ffdcfeed57fbd444eaccd35305bd49ef21aaff1504f9b00', 2, 22, None, {30:'boolean',49:'exception-type',50:'int32',51:'boolean',53:'boolean',55:'boolean'}),

 'SchemaNameCollectionComparisonTests.Invalid_indexer_exception_type_matches_microsoft':
 ('7719e6843503855de63a598ca83b2d4cf72ec16d759c317403f60100e5200e8d', 4, 8, None, {274:'exception-type',275:'null'}),

 'DirectoryEntryDisposedWrapperComparisonTests.Property_wrapper_access_after_dispose_matches_microsoft':
 ('214e95cc5dbe38b9f1d18b19612c82558de5cf3a4ba6756e97306f1c52526fe4', 10, 28, None, {45:'exception-type|null',46:'null',48:'boolean|null'}),

}
# Additional independently reviewed method/site manifests; no automatic site admission.
METHOD_KINDS = {name:'Theory' for name in METHODS}
EXTRA_SPECS = json.loads((ROOT/'offline-extra-spec.json').read_text())
for spec in EXTRA_SPECS:
 if spec['method'] in METHODS: raise ValueError('Duplicate reviewed method')
 kind = spec.get('kind','Theory')
 if kind not in ('Fact','Theory') or (kind=='Fact' and spec['rows']!=1):
  raise ValueError('Invalid source method kind or Fact execution count')
 METHOD_KINDS[spec['method']] = kind
 METHODS[spec['method']] = (spec['sha'],spec['rows'],spec['checks'],spec.get('member'),
                            {line:kind for line,member,kind in spec['sites']})

EXCEPTIONS = {'System.ArgumentException','System.ArgumentNullException','System.ObjectDisposedException','System.InvalidOperationException','System.ArgumentOutOfRangeException','System.InvalidCastException','System.IndexOutOfRangeException','System.NotSupportedException','System.Runtime.InteropServices.COMException',
 'System.ComponentModel.InvalidEnumArgumentException','ArgumentException',
 'ArgumentNullException','COMException','DirectoryServicesCOMException','PrincipalOperationException','ObjectDisposedException','NullReferenceException','InvalidOperationException'}

def sha(text):
 return hashlib.sha256(text.encode()).hexdigest()

def shared_source_hashes(specs, sources):
    hashes={}
    for spec in specs:
        references=spec.get('relatedSources',[])
        if type(references) is not list: raise ValueError('Invalid shared scenario source review')
        for reference in references:
            if type(reference) is not dict or set(reference)!={'file','sourceSha256','review'}:
                raise ValueError('Invalid shared scenario source review')
            filename=reference.get('file')
            expected=reference.get('sourceSha256')
            if (type(filename) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*\.cs',filename)
                    or type(expected) is not str or not re.fullmatch(r'[0-9a-f]{64}',expected)
                    or type(reference.get('review')) is not str or not reference['review'].strip()):
                raise ValueError('Invalid shared scenario source review')
            path=(SOURCE/filename).resolve()
            if not path.is_relative_to(SOURCE.resolve()): raise ValueError('Invalid shared scenario source path')
            raw=sources[filename] if filename in sources else path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=expected:
                raise ValueError('Shared scenario source changed: '+filename)
            if filename in hashes and hashes[filename]!=expected: raise ValueError('Conflicting shared scenario source review')
            hashes[filename]=expected
    return hashes

def validate_input_projection(spec, source=None):
    projection=spec.get('inputProjection')
    if projection is None: return None
    keys={'kind','sourceDeclaredInputs','includedInputs','excludedInputs','review'}
    if type(projection) is not dict or set(projection)!=keys:
        raise ValueError('Invalid reviewed input projection fields')
    included,excluded=projection['includedInputs'],projection['excludedInputs']
    declared=projection['sourceDeclaredInputs']
    if (spec.get('kind','Theory')!='Theory' or not spec.get('adaptation')
            or type(spec['rows']) is not int or spec['rows']<=0
            or projection['kind']!='reviewed-source-branch-subset'
            or type(declared) is not int or declared<=0
            or type(included) is not list or type(excluded) is not list
            or not included or not excluded
            or any(type(value) is not str or not value for value in included+excluded)
            or len(set(included+excluded))!=len(included+excluded)
            or len(included)!=spec['rows'] or declared!=len(included)+len(excluded)
            or type(projection['review']) is not str or not projection['review'].strip()):
        raise ValueError('Invalid reviewed source-branch input subset')
    if source is not None:
        # This reviewed scope supports simple single-string InlineData labels.
        # Ambiguous/dynamic/multi-argument rows need a different explicit review.
        labels=re.findall(r'\[\s*InlineData\(\s*"([^"\\]*)"\s*\)\s*\]',source.decode())
        if len(labels)!=declared or set(labels)!=set(included+excluded):
            raise ValueError('Input subset labels disagree with pinned source inputs')
    return projection

def validate_record_pins(spec):
    records=spec.get('reviewedRecords')
    if spec.get('maxOccurrences') and records is None:
        raise ValueError('Shared-helper admission requires reviewed record identities')
    if records is not None:
        if set(records)!= {'net8.0-windows','net10.0-windows'}:
            raise ValueError('Invalid reviewed record frameworks')
        for framework,identities in records.items():
            excluded=set(spec.get('excludedCloneHelperRecords',{}).get(framework,[]))
            excluded.update(spec.get('excludedLiteralHelperRecords',{}).get(framework,[]))
            excluded.update(spec.get('excludedMicrosoftOnlyHelperRecords',{}).get(framework,[]))
            if (type(identities) is not list or len(identities)!=spec['checks']
                    or any(type(value) is not int or value<=0 for value in identities)
                    or len(set(identities))!=len(identities) or set(identities)&excluded):
                raise ValueError('Invalid reviewed helper record identities')
    return records

def extract(rows, sources=None):
 if sources is None:
  sources = {name.split('.')[0]+'.cs': (SOURCE / (name.split('.')[0]+'.cs')).read_bytes() for name in METHODS}
 lookup = {}
 shared=shared_source_hashes(EXTRA_SPECS,sources)
 for spec in EXTRA_SPECS: validate_input_projection(spec,sources[spec['file']])
 for name, (source_hash, _, _, member, sites) in METHODS.items():
  cls, method = name.split('.')
  filename = cls+'.cs'
  if hashlib.sha256(sources[filename]).hexdigest() != source_hash:
   raise ValueError('Reviewed source changed: '+filename)
  full = 'AdForLinux.DifferentialTests.'+name
  site_map = {sha('\0'.join([full,filename,member or method,str(line),'value','explicit-microsoft-comparison'])): (line,kind) for line,kind in sites.items()}
  lookup[sha(full)] = name, site_map
 result = {'schemaVersion':1,'sourceCommit':COMMIT,'runId':43105205156,'jobId':130806631589,
           'coverage':'partial-offline-method-scalar-multisets','methodKinds':METHOD_KINDS,'sourceSha256':{n.split('.')[0]+'.cs':s[0] for n,s in METHODS.items()},'frameworks':{}}
 for filename,expected_hash in shared.items():
  if filename in result['sourceSha256'] and result['sourceSha256'][filename]!=expected_hash:
   raise ValueError('Conflicting main/shared scenario source review')
  result['sourceSha256'][filename]=expected_hash
 record_pins = {spec['method']:validate_record_pins(spec) for spec in EXTRA_SPECS}
 limits = {spec['method']:spec.get('maxOccurrences',{}) for spec in EXTRA_SPECS}
 occurrence_counts = collections.Counter()
 seen = set()
 groups = collections.defaultdict(lambda: collections.defaultdict(list))
 for row in rows:
  framework = row['framework']
  if framework not in ('net8.0-windows','net10.0-windows') or row['commit'] != COMMIT or row['kind'] != 'reviewed-scalar-pair':
   raise ValueError('Unexpected provenance')
  identity = framework, row['record']
  if type(row['record']) is not int or row['record'] <= 0 or identity in seen:
   raise ValueError('Duplicate/invalid public record')
  seen.add(identity)
  if row['testMethodSha256'] not in lookup:
   raise ValueError('Unreviewed method')
  name, sites = lookup[row['testMethodSha256']]
  if row['sourceSiteSha256'] not in sites:
   raise ValueError('Unreviewed source site')
  line, kind = sites[row['sourceSiteSha256']]
  pins = record_pins.get(name)
  if pins is not None and row['record'] not in pins[framework]:
   raise ValueError('Unreviewed helper invocation record identity')
  operand = row['microsoftExpectedObservation']
  value = operand['value']
  if operand['type'] not in kind.split('|'):
   raise ValueError('Unexpected scalar type')
  kind = operand['type']
  if kind == 'null':
   if value is not None: raise ValueError('Invalid null')
   token = 'n'
  elif kind == 'boolean':
   if type(value) is not bool: raise ValueError('Invalid boolean')
   token = 'b1' if value else 'b0'
  elif kind == 'int32':
   if type(value) is not int or not -(2**31) <= value < 2**31: raise ValueError('Invalid Int32')
   token = 'i32:'+str(value)
  else:
   if type(value) is not str or value not in EXCEPTIONS: raise ValueError('Unreviewed exception type')
   token = 'e:'+value
  execution = row['execution']
  if type(execution) is not str or len(execution) != 32 or any(c not in '0123456789abcdef' for c in execution):
   raise ValueError('Invalid execution identity')
  occurrence = framework,name,execution,line
  occurrence_counts[occurrence] += 1
  maximum = limits.get(name,{}).get(str(line))
  if maximum is not None and occurrence_counts[occurrence] > maximum:
   raise ValueError('Unreviewed helper invocation')
  groups[framework,name][execution].append((row['record'],str(line)+'='+token))
 for framework in ('net8.0-windows','net10.0-windows'):
  methods = {}
  for name, (_, executions, checks, _, _) in METHODS.items():
   captured = groups[framework,name]
   if len(captured) != executions or sum(map(len,captured.values())) != checks:
    raise ValueError('Missing/extra executions or scalar observations: '+name)
   sequences = [','.join(token for _,token in sorted(values)) for values in captured.values()]
   methods[name] = sorted(sequences)
  result['frameworks'][framework] = methods
 return result

if __name__ == '__main__':
 rows = [json.loads(line) for line in (ROOT/'offline-observations.jsonl').read_text().splitlines()]
 output = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'offline-oracle.json'
 output.write_text(json.dumps(extract(rows),indent=2)+'\n')
