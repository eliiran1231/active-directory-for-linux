import copy
import json
import pathlib
import unittest
from unittest.mock import patch
from extract_hardcoded import extract, csharp_fixture, SPECS

ROOT=pathlib.Path(__file__).parent

class HardcodedProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((ROOT/'hardcoded-observations.json').read_text())

    def test_public_records_reproduce_existing_fixture(self):
        result=extract(self.data)
        self.assertEqual(set(result),{'net8.0-windows','net10.0-windows'})
        for values in result.values():
            self.assertEqual(values,csharp_fixture())
            self.assertEqual(sum(map(len,values.values())),78)

    def test_csharp_fixture_scalar_types_are_preserved(self):
        path=ROOT/'HardcodedExpectations.g.cs'
        original=path.read_text()
        for before,after in [('= [false]','= [0]'),('2147483648L','2147483648')]:
            changed=original.replace(before,after,1)
            self.assertNotEqual(changed,original)
            with patch('pathlib.Path.read_text',return_value=changed):
                with self.assertRaisesRegex(ValueError,'fixture scalar type'): csharp_fixture()

    def test_source_or_operand_role_changes_are_rejected(self):
        with patch('pathlib.Path.read_bytes',return_value=b'changed source'):
            with self.assertRaisesRegex(ValueError,'source changed'): extract(self.data)
        self.data['rows'][0]['sourceSiteSha256']='0'*64
        with self.assertRaisesRegex(ValueError,'Unreviewed source'): extract(self.data)

    def test_clone_payloads_and_guessed_case_labels_are_rejected(self):
        for field in ('cloneObservation','caseLabel'):
            changed=copy.deepcopy(self.data);changed['rows'][0][field]='unexpected'
            with self.assertRaisesRegex(ValueError,'record fields'): extract(changed)
        self.data['recordKind']='reviewed-scalar-pair'
        with self.assertRaisesRegex(ValueError,'provenance'): extract(self.data)

    def test_missing_duplicate_and_unordered_records_are_rejected(self):
        changed=copy.deepcopy(self.data);changed['rows'].pop()
        with self.assertRaisesRegex(ValueError,'Missing or extra'): extract(changed)
        changed=copy.deepcopy(self.data);changed['rows'].insert(1,changed['rows'][0])
        with self.assertRaisesRegex(ValueError,'Duplicate or unordered'): extract(changed)
        self.data['rows'][0],self.data['rows'][1]=self.data['rows'][1],self.data['rows'][0]
        with self.assertRaisesRegex(ValueError,'Duplicate or unordered'): extract(self.data)

    def test_boolean_integer_alias_and_overflow_are_rejected(self):
        for kind,bad in [('boolean',1),('int32',True),('int32',2**31),('int64',2**63)]:
            changed=copy.deepcopy(self.data)
            row=next(r for r in changed['rows'] if r['operand']['type']==kind)
            row['operand']['value']=bad
            with self.assertRaisesRegex(ValueError,'scalar value'): extract(changed)
        changed=copy.deepcopy(self.data)
        next(r for r in changed['rows'] if r['operand']['type']=='exception-type')['operand']['value']='Unknown.Exception'
        with self.assertRaisesRegex(ValueError,'scalar value'): extract(changed)

    def test_fact_identity_and_public_provenance_are_required(self):
        changed=copy.deepcopy(self.data)
        # Several source sites share each Fact execution: a new GUID must fail.
        changed['rows'][0]['execution']='0'*32
        with self.assertRaisesRegex(ValueError,'Fact requires|Execution reused'): extract(changed)
        for field,bad in [('runId',0),('jobId',True),('sourceCommit','0'*40)]:
            changed=copy.deepcopy(self.data);changed[field]=bad
            with self.assertRaisesRegex(ValueError,'provenance'): extract(changed)

if __name__=='__main__': unittest.main()
