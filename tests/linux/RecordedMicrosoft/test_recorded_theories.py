import copy
import json
import pathlib
import unittest
from extract_recorded_theories import extract,csharp_fixture,SPECS,SOURCE,TYPES

ROOT=pathlib.Path(__file__).parent

class OriginalTheoryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((ROOT/'theory-observations.json').read_text())
        self.sources={s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}

    def test_reproduces_the_original_eight_theory_multisets(self):
        oracle=extract(self.data,self.sources)
        self.assertEqual(oracle,csharp_fixture())
        self.assertEqual(len(oracle),16)
        for framework in self.data['frameworks']:
            rows=[rows for key,rows in oracle.items() if key.startswith(framework+'|')]
            self.assertEqual(sum(map(len,rows)),80)
            self.assertEqual(sum(len(value.split(',')) for values in rows for value in values),1369)

    def test_int64_boundaries_preserve_every_bit(self):
        expected=extract(self.data,self.sources)
        self.assertTrue(any('i64:21474836470000001' in value for values in expected.values() for value in values))
        for bad in (21474836470000000,21474836470000000.0,'01','+1','-0','9223372036854775808','-9223372036854775809'):
            data=copy.deepcopy(self.data)
            observation=next(row for group in data['groups'] for row in group[3]
                             if row[2]==TYPES.index('int64') and row[3]=='21474836470000001')
            observation[3]=bad
            with self.subTest(value=bad),self.assertRaisesRegex(ValueError,'Int64'):
                extract(data,self.sources)
        data=copy.deepcopy(self.data)
        observation=next(row for group in data['groups'] for row in group[3]
                         if row[2]==TYPES.index('int64') and row[3]=='21474836470000001')
        observation[3]='21474836470000000'
        self.assertNotEqual(extract(data,self.sources),expected)

    def test_stale_source_and_unreviewed_site_are_rejected(self):
        self.sources[SPECS[0]['file']]+=b' '
        with self.assertRaisesRegex(ValueError,'source changed'):
            extract(self.data,self.sources)
        self.sources={s['file']:(SOURCE/s['file']).read_bytes() for s in SPECS}
        data=copy.deepcopy(self.data);data['sites'][0]='0'*64
        with self.assertRaises(ValueError):extract(data,self.sources)

    def test_alias_indices_invalid_guids_and_duplicate_counters_are_rejected(self):
        changes=[lambda d:d['groups'][0].__setitem__(0,True),
                 lambda d:d['groups'][0][3][0].__setitem__(0,True),
                 lambda d:d['groups'][0][3][0].__setitem__(1,False),
                 lambda d:d['groups'][0][3][0].__setitem__(2,True),
                 lambda d:d['executions'].__setitem__(0,'bad'),
                 lambda d:d['groups'][0][3].append(copy.deepcopy(d['groups'][0][3][0])),
                 lambda d:d['groups'].append(copy.deepcopy(d['groups'][0]))]
        for change in changes:
            data=copy.deepcopy(self.data);change(data)
            with self.assertRaises(ValueError):extract(data,self.sources)

    def test_missing_group_or_changed_record_order_is_rejected(self):
        data=copy.deepcopy(self.data);data['groups'].pop()
        with self.assertRaises(ValueError):extract(data,self.sources)
        data=copy.deepcopy(self.data)
        group=next(g for g in data['groups'] if len(g[3])>1)
        group[3][0],group[3][1]=group[3][1],group[3][0]
        with self.assertRaisesRegex(ValueError,'counter'):extract(data,self.sources)

    def test_scalar_aliases_and_unreviewed_exception_identifiers_are_rejected(self):
        for kind,bad in [('int32',True),('boolean',1),('null','not-null'),('exception-type','unreviewed-message')]:
            data=copy.deepcopy(self.data)
            observation=next(row for group in data['groups'] for row in group[3] if row[2]==TYPES.index(kind))
            observation[3]=bad
            with self.subTest(kind=kind),self.assertRaises(ValueError):extract(data,self.sources)

    def test_clone_fields_row_labels_and_provenance_changes_are_rejected(self):
        for key,value in [('cloneValues',[]),('caseIdentityMapping','guessed'),('sourceCommit','0'*40),
                          ('recordKind','unverified-assertion-operand'),('schemaVersion',True),('runId',1)]:
            data=copy.deepcopy(self.data);data[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):extract(data,self.sources)
        data=copy.deepcopy(self.data);data['groups'][0][3][0].append('clone-value')
        with self.assertRaisesRegex(ValueError,'Microsoft-only'):extract(data,self.sources)

if __name__=='__main__':unittest.main()
