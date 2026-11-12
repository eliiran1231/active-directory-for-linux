import copy
import json
import pathlib
import unittest

from extract_offline_oracle import extract, METHODS, SOURCE

ROOT = pathlib.Path(__file__).parent

class OfflineAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(line) for line in (ROOT/'offline-observations.jsonl').read_text().splitlines()]
        self.sources = {name.split('.')[0]+'.cs': (SOURCE/(name.split('.')[0]+'.cs')).read_bytes() for name in METHODS}

    def test_reproduces_fixture_and_coverage(self):
        oracle = extract(self.rows, self.sources)
        self.assertEqual(oracle, json.loads((ROOT/'offline-oracle.json').read_text()))
        for methods in oracle['frameworks'].values():
            self.assertEqual(len(methods), 8)
            self.assertEqual(sum(map(len, methods.values())), 56)
            self.assertEqual(sum(len(sequence.split(',')) for rows in methods.values() for sequence in rows), 197)

    def test_changed_source_rejected(self):
        filename = next(iter(self.sources))
        self.sources[filename] += b' '
        with self.assertRaisesRegex(ValueError, 'source changed'):
            extract(self.rows, self.sources)

    def test_missing_and_duplicate_observations_rejected(self):
        for rows in (self.rows[1:], self.rows+[self.rows[0]]):
            with self.subTest(length=len(rows)), self.assertRaises(ValueError):
                extract(rows, self.sources)

    def test_missing_execution_rejected(self):
        first = self.rows[0]
        rows = [r for r in self.rows if (r['framework'],r['execution']) != (first['framework'],first['execution'])]
        with self.assertRaises(ValueError):
            extract(rows, self.sources)

    def test_changed_provenance_and_site_rejected(self):
        for key, value in [('commit','0'*40), ('kind','unverified-assertion-operand'),
                           ('framework','net9.0-windows'), ('sourceSiteSha256','0'*64),
                           ('testMethodSha256','0'*64), ('execution','bad')]:
            rows = copy.deepcopy(self.rows)
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                extract(rows, self.sources)

    def test_wrong_scalar_types_rejected(self):
        for kind,value in [('int32',False), ('boolean',1), ('null','not-null'),
                           ('exception-type','arbitrary string')]:
            rows = copy.deepcopy(self.rows)
            target = next(r for r in rows if r['microsoftExpectedObservation']['type'] == kind)
            target['microsoftExpectedObservation']['value'] = value
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                extract(rows, self.sources)

    def test_clone_operands_do_not_supply_expectations(self):
        oracle = extract(self.rows, self.sources)
        for row in self.rows:
            row['ourActualObservation'] = {'type':'int32','value':12345}
        self.assertEqual(oracle, extract(self.rows, self.sources))

    def test_input_order_does_not_change_execution_order(self):
        self.assertEqual(extract(self.rows, self.sources), extract(list(reversed(self.rows)), self.sources))

if __name__ == '__main__':
    unittest.main()
