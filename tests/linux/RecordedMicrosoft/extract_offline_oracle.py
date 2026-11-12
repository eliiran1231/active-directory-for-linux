"""Source-reviewed admission for eight offline theories from the public job log.

Only Microsoft operands at the explicit Comparison.Check sites below are admitted.
No execution GUID is assigned to a theory input: output is a method multiset.
"""
import collections
import hashlib
import json
import pathlib
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

}
EXCEPTIONS = {'System.ArgumentException','System.ArgumentNullException','System.ObjectDisposedException','System.InvalidOperationException','System.ArgumentOutOfRangeException','System.InvalidCastException','System.IndexOutOfRangeException',
 'System.ComponentModel.InvalidEnumArgumentException','ArgumentException',
 'ArgumentNullException','ObjectDisposedException','NullReferenceException'}

def sha(text):
 return hashlib.sha256(text.encode()).hexdigest()

def extract(rows, sources=None):
 if sources is None:
  sources = {name.split('.')[0]+'.cs': (SOURCE / (name.split('.')[0]+'.cs')).read_bytes() for name in METHODS}
 lookup = {}
 for name, (source_hash, _, _, member, sites) in METHODS.items():
  cls, method = name.split('.')
  filename = cls+'.cs'
  if hashlib.sha256(sources[filename]).hexdigest() != source_hash:
   raise ValueError('Reviewed source changed: '+filename)
  full = 'AdForLinux.DifferentialTests.'+name
  site_map = {sha('\0'.join([full,filename,member or method,str(line),'value','explicit-microsoft-comparison'])): (line,kind) for line,kind in sites.items()}
  lookup[sha(full)] = name, site_map
 result = {'schemaVersion':1,'sourceCommit':COMMIT,'runId':43105205156,'jobId':130806631589,
           'coverage':'partial-eight-offline-theory-method-multisets','sourceSha256':{n.split('.')[0]+'.cs':s[0] for n,s in METHODS.items()},'frameworks':{}}
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
  operand = row['microsoftExpectedObservation']
  value = operand['value']
  if operand['type'] != kind:
   raise ValueError('Unexpected scalar type')
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
