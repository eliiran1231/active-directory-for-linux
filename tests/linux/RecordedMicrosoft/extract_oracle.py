"""Admit only reviewed Microsoft property reads in four parameterless Facts.
Input is the public sanitized job JSONL, never private capture files.
"""
import hashlib,json,pathlib,sys
SOURCE_SHA='57daa564ee766aee7080cd3eef8a834627105dbc49eecf09cfe239a513250143'
COMMIT='93f1f9c6b593d9f4dd38d23616632dc6a015f4ca'
CLASS='AdForLinux.DifferentialTests.DirectorySearchOptionsComparisonTests.'
METHODS={
'Directory_searcher_security_mask_validation_matches_microsoft':[(142,'SecurityMasks',16),(149,'SecurityMasks',1),(156,'SecurityMasks',2)],
'Virtual_list_view_constructors_match_microsoft':[(n,p,6) for n,p in [(241,'BeforeCount'),(242,'AfterCount'),(243,'Offset'),(244,'ApproximateTotal'),(245,'TargetPercentage'),(247,'ContextNull')]],
'Virtual_list_view_validation_and_derived_values_match_microsoft':[(n,p,3) for n,p in [(241,'BeforeCount'),(242,'AfterCount'),(243,'Offset'),(244,'ApproximateTotal'),(245,'TargetPercentage'),(247,'ContextNull')]],
'Virtual_list_view_response_update_uses_the_returned_total_for_percentage':[(n,p,1) for n,p in [(241,'BeforeCount'),(242,'AfterCount'),(243,'Offset'),(244,'ApproximateTotal'),(245,'TargetPercentage'),(247,'ContextNull')]]}
def sha(s):return hashlib.sha256(s.encode()).hexdigest()
def extract(rows, source):
 if hashlib.sha256(source).hexdigest()!=SOURCE_SHA:raise ValueError('Reviewed source changed')
 result={'schemaVersion':1,'sourceCommit':COMMIT,'sourceFileSha256':SOURCE_SHA,'runId':43105205156,'jobId':130806631589,'coverage':'partial-four-parameterless-facts','frameworks':{}}
 for framework in ('net8.0-windows','net10.0-windows'):
  out={}
  seen_records=set()
  for method,sites in METHODS.items():
   candidates=[r for r in rows if r.get('framework')==framework and r.get('testMethodSha256')==sha(CLASS+method)]
   for r in candidates:
    record=r.get('record')
    if type(record) is not int or record<=0 or record in seen_records:raise ValueError('Duplicate or invalid public record')
    seen_records.add(record)
    execution=r.get('execution')
    if type(execution) is not str or len(execution)!=32 or any(c not in '0123456789abcdef' for c in execution):raise ValueError('Invalid execution identity')
   if len({r['execution'] for r in candidates})!=1:raise ValueError('Missing or ambiguous Fact execution')
   props={}
   for line,prop,count in sites:
    member=method if line<200 else 'AssertViewsEqual'
    site=sha('\0'.join([CLASS+method,'DirectorySearchOptionsComparisonTests.cs',member,str(line),'assert-equal-expected','assertion-operand-unverified']))
    matches=sorted((r for r in candidates if r.get('sourceSiteSha256')==site),key=lambda r:r['record'])
    if len(matches)!=count or len({r['record'] for r in matches})!=count:raise ValueError('Missing, duplicate, or unexpected occurrence')
    values=[]
    for r in matches:
     expected='boolean' if prop=='ContextNull' else 'int32'
     if r['commit']!=COMMIT or r['kind']!='unverified-assertion-operand' or r['operand']['type']!=expected:raise ValueError('Unexpected provenance/type')
     value=r['operand']['value']
     if type(value) is not (bool if expected=='boolean' else int):raise ValueError('Invalid typed value')
     if expected=='int32' and not -(2**31)<=value<2**31:raise ValueError('Int32 outside declared range')
     values.append(value)
    props[str(line)]={'property':prop,'sourceSiteSha256':site,'values':values,'publicRecordNumbers':[r['record'] for r in matches]}
   out[method]=props
  result['frameworks'][framework]=out
 return result
if __name__=='__main__':
 rows=[json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text().splitlines()]
 source=pathlib.Path(__file__).parents[2]/'windows/AdForLinux.DifferentialTests/DirectorySearchOptionsComparisonTests.cs'
 pathlib.Path(sys.argv[2]).write_text(json.dumps(extract(rows,source.read_bytes()),indent=2)+'\n')
