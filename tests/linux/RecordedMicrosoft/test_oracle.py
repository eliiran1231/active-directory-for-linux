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
 def test_coverage_count(self):
  oracle=extract(self.rows,self.source)
  for methods in oracle['frameworks'].values():
   self.assertEqual(len(methods),4)
   self.assertEqual(sum(len(site['values']) for sites in methods.values() for site in sites.values()),79)
if __name__=='__main__':unittest.main()
