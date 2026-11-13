import copy,json,pathlib,unittest
from extract_oracle import extract, SOURCE_SHA
ROOT=pathlib.Path(__file__).parent
class AdmissionTests(unittest.TestCase):
 def setUp(self):
  self.rows=[json.loads(l) for l in (ROOT/'observations.jsonl').read_text().splitlines()]
  self.source=(ROOT.parents[1]/'windows/AdForLinux.DifferentialTests/DirectorySearchOptionsComparisonTests.cs').read_bytes()
 def test_reproduces_exact_fixture(self):
  self.assertEqual(extract(self.rows,self.source),json.loads((ROOT/'oracle.json').read_text()))
 def test_missing_occurrence_rejected(self):
  with self.assertRaises(ValueError):extract(self.rows[1:],self.source)
 def test_duplicate_rejected(self):
  with self.assertRaises(ValueError):extract(self.rows+[self.rows[0]],self.source)
 def test_changed_source_rejected(self):
  with self.assertRaises(ValueError):extract(self.rows,self.source+b' ')
 def test_changed_provenance_rejected(self):
  self.rows[0]['commit']='0'*40
  with self.assertRaises(ValueError):extract(self.rows,self.source)
 def test_second_execution_rejected(self):
  self.rows[0]['execution']='0'*32
  with self.assertRaises(ValueError):extract(self.rows,self.source)
 def test_wrong_type_rejected(self):
  self.rows[0]['operand']['type']='string'
  with self.assertRaises(ValueError):extract(self.rows,self.source)
 def test_boolean_not_integer(self):
  self.rows[0]['operand']['value']=False
  with self.assertRaises(ValueError):extract(self.rows,self.source)
 def test_int32_range_rejected(self):
  for value in (2**31,-(2**31)-1):
   rows=copy.deepcopy(self.rows)
   next(r for r in rows if r['operand']['type']=='int32')['operand']['value']=value
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'Int32'):
    extract(rows,self.source)
 def test_invalid_public_record_rejected(self):
  for value in (0,-1,True,'1'):
   rows=copy.deepcopy(self.rows);rows[0]['record']=value
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'public record'):
    extract(rows,self.source)
 def test_duplicate_record_across_sites_rejected(self):
  rows=copy.deepcopy(self.rows)
  first=rows[0]
  other=next(r for r in rows if r['framework']==first['framework'] and r['sourceSiteSha256']!=first['sourceSiteSha256'])
  first['record']=other['record']
  with self.assertRaisesRegex(ValueError,'public record'):
   extract(rows,self.source)
 def test_invalid_execution_identity_rejected(self):
  for value in ('g'*32,'0'*31,True):
   rows=copy.deepcopy(self.rows)
   group=rows[0]['framework'],rows[0]['testMethodSha256']
   for row in rows:
    if (row['framework'],row['testMethodSha256'])==group:row['execution']=value
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'execution identity'):
    extract(rows,self.source)
 def test_coverage_count(self):
  oracle=extract(self.rows,self.source)
  for methods in oracle['frameworks'].values():
   self.assertEqual(len(methods),4)
   self.assertEqual(sum(len(site['values']) for sites in methods.values() for site in sites.values()),79)
if __name__=='__main__':unittest.main()
