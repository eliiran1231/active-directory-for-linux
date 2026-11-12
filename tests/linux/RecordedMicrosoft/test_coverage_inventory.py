import json
import pathlib
import unittest
from coverage_inventory import build, mirror_methods

ROOT=pathlib.Path(__file__).parent

class CoverageLedgerTests(unittest.TestCase):
    def test_reproduces_full_ledger_with_distinct_methods(self):
        ledger=build()
        self.assertEqual(ledger,json.loads((ROOT/'coverage-inventory.json').read_text()))
        self.assertEqual(ledger['summary']['sourceDeclarations'],359)
        self.assertEqual(ledger['summary']['distinctPartiallyMirroredMethods'],44)
        self.assertEqual(ledger['summary']['fullyMirroredMethods'],0)
        self.assertEqual(ledger['summary']['notMirroredMethods'],315)
        self.assertFalse(ledger['summary']['allCasesCovered'])
        mirrored=mirror_methods()
        overlap=[name for name,groups in mirrored.items() if 'structured-four-fact-oracle' in groups and 'hardcoded-source-reviewed-operands' in groups]
        self.assertEqual(len(overlap),2)

if __name__=='__main__': unittest.main()
