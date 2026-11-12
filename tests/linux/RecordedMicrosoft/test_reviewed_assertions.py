import copy
import json
import pathlib
import unittest
from extract_reviewed_assertions import extract, SPECS, SOURCE, sha

ROOT = pathlib.Path(__file__).parent

class ReviewedAssertionAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(line) for line in (ROOT/'reviewed-assertions.jsonl').read_text().splitlines()]
        self.sources = {s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}

    def test_reproduces_fixture_and_coverage(self):
        oracle = extract(self.rows,self.sources)
        self.assertEqual(oracle,json.loads((ROOT/'reviewed-assertions-oracle.json').read_text()))
        for methods in oracle['frameworks'].values():
            self.assertEqual(len(methods),14)
            self.assertEqual(sum(map(len,methods.values())),54)
            self.assertEqual(sum(len(sequence.split(',')) for rows in methods.values() for sequence in rows),172)

    def test_changed_source_rejected(self):
        self.sources[next(iter(self.sources))] += b' '
        with self.assertRaises(ValueError): extract(self.rows,self.sources)

    def test_missing_or_duplicate_record_rejected(self):
        for rows in (self.rows[1:],self.rows+[self.rows[0]]):
            with self.subTest(length=len(rows)), self.assertRaises(ValueError): extract(rows,self.sources)

    def test_clone_operand_role_rejected(self):
        spec = SPECS[0]
        line,member,_ = spec['sites'][0]
        full = 'AdForLinux.DifferentialTests.'+spec['method']
        rows = copy.deepcopy(self.rows)
        target = next(r for r in rows if r['testMethodSha256'] == sha(full))
        target['sourceSiteSha256'] = sha('\0'.join([full,spec['file'],member or spec['method'].split('.')[1],str(line),'assert-equal-actual','assertion-operand-unverified']))
        with self.assertRaisesRegex(ValueError,'operand role'): extract(rows,self.sources)

    def test_literal_expected_site_rejected(self):
        spec = SPECS[4]
        full = 'AdForLinux.DifferentialTests.'+spec['method']
        rows = copy.deepcopy(self.rows)
        target = next(r for r in rows if r['testMethodSha256'] == sha(full))
        target['sourceSiteSha256'] = sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],'198','assert-equal-expected','assertion-operand-unverified']))
        with self.assertRaises(ValueError): extract(rows,self.sources)

    def test_provenance_type_and_value_rejected(self):
        for key,value in [('commit','0'*40),('framework','net9.0-windows'),('kind','reviewed-scalar-pair'),('execution','bad')]:
            rows = copy.deepcopy(self.rows)
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): extract(rows,self.sources)
        rows = copy.deepcopy(self.rows)
        target = next(r for r in rows if r['operand']['type']=='int32')
        target['operand']['value'] = False
        with self.assertRaises(ValueError): extract(rows,self.sources)

    def test_public_order_does_not_invent_input_mapping(self):
        self.assertEqual(extract(self.rows,self.sources),extract(list(reversed(self.rows)),self.sources))

if __name__ == '__main__': unittest.main()
