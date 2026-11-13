import copy
import json
import pathlib
import unittest
from unittest import mock

from extract_offline_oracle import extract, METHODS, SOURCE, sha, EXTRA_SPECS

ROOT = pathlib.Path(__file__).parent

class OfflineAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(line) for line in (ROOT/'offline-observations.jsonl').read_text().splitlines()]
        self.sources = {name.split('.')[0]+'.cs': (SOURCE/(name.split('.')[0]+'.cs')).read_bytes() for name in METHODS}

    def test_reproduces_fixture_and_coverage(self):
        oracle = extract(self.rows, self.sources)
        self.assertEqual(oracle, json.loads((ROOT/'offline-oracle.json').read_text()))
        for methods in oracle['frameworks'].values():
            facts={name for name,kind in oracle['methodKinds'].items() if kind=='Fact'}
            self.assertEqual(len(facts),26)
            self.assertTrue(all(len(methods[name])==1 for name in facts))
            self.assertEqual(sum(len(rows) for name,rows in methods.items() if name not in facts),267)
            self.assertEqual(len(methods), 77)
            self.assertEqual(sum(map(len, methods.values())), 293)
            self.assertEqual(sum(len(sequence.split(',')) for rows in methods.values() for sequence in rows), 920)

    def test_shared_saved_user_fixture_dependency_cannot_go_stale(self):
        original=pathlib.Path.read_bytes
        def changed(path):
            return b'changed creation lifecycle' if path.name=='CompatibilityCachedLogonProjectionComparisonTests.cs' else original(path)
        with mock.patch('pathlib.Path.read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'Shared scenario source changed'):
                extract(self.rows,self.sources)

    def test_retained_wrapper_error_is_not_admitted_by_identity_projection(self):
        name='CompatibilityPrincipalCurrentOwnershipComparisonTests.Repeated_Current_returns_matching_wrapper_ownership'
        full='AdForLinux.DifferentialTests.'+name
        cls,member=name.split('.')
        rows=copy.deepcopy(self.rows)
        target=next(row for row in rows if row['testMethodSha256']==sha(full))
        target['sourceSiteSha256']=sha('\0'.join([full,cls+'.cs',member,'67','value','explicit-microsoft-comparison']))
        target['microsoftExpectedObservation']={'type':'null','value':None}
        with self.assertRaisesRegex(ValueError,'Unreviewed source site'):
            extract(rows,self.sources)

    def test_options_helpers_exclude_microsoft_only_targets_and_portable_literals(self):
        rejected=json.loads((ROOT/'rejected-options-helper.json').read_text())['rows']
        self.assertEqual(len(rejected),2)
        for replacement in rejected:
            rows=copy.deepcopy(self.rows)
            index=next(i for i,r in enumerate(rows) if r['framework']==replacement['framework']
                       and r['execution']==replacement['execution']
                       and r['testMethodSha256']==replacement['testMethodSha256']
                       and r['sourceSiteSha256']==replacement['sourceSiteSha256'])
            rows[index]=replacement
            with self.subTest(record=replacement['record']),self.assertRaisesRegex(ValueError,'helper invocation record identity'):
                extract(rows,self.sources)

    def test_disposed_entry_live_search_phase_is_not_an_oracle_site(self):
        name='DirectoryEntryComparisonTests.Disposed_entry_lifecycle_matches_for_cached_and_uncached_entries'
        full='AdForLinux.DifferentialTests.'+name
        cls,member=name.split('.')
        for line in (98,99,103):
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full))
            target['sourceSiteSha256']=sha('\0'.join([full,cls+'.cs',member,str(line),'value','explicit-microsoft-comparison']))
            target['microsoftExpectedObservation']={'type':'null','value':None}
            with self.subTest(line=line),self.assertRaisesRegex(ValueError,'Unreviewed source site'):
                extract(rows,self.sources)

    def test_literal_native_identity_expected_operand_is_not_an_oracle_site(self):
        name = 'CompatibilitySearcherConstructionPagingComparisonTests.Deferred_filter_assignment_preserves_constructor_paging_state'
        full = 'AdForLinux.DifferentialTests.' + name
        cls, member = name.split('.')
        rows = copy.deepcopy(self.rows)
        target = next(row for row in rows if row['testMethodSha256'] == sha(full))
        target['sourceSiteSha256'] = sha('\0'.join([full, cls+'.cs', member, '54', 'value', 'explicit-microsoft-comparison']))
        target['microsoftExpectedObservation'] = {'type':'boolean', 'value':True}
        with self.assertRaisesRegex(ValueError, 'Unreviewed source site'):
            extract(rows, self.sources)

    def test_shared_query_helper_caller_identity_is_required(self):
        name='PrincipalSearcherComparisonTests.Group_QBE_filters_match'
        full='AdForLinux.DifferentialTests.'+name
        cls,member=name.split('.')
        rows=copy.deepcopy(self.rows)
        target=next(row for row in rows if row['testMethodSha256']==sha(full))
        target['sourceSiteSha256']=sha('\0'.join([full,cls+'.cs',member,'460','value','explicit-microsoft-comparison']))
        with self.assertRaisesRegex(ValueError,'Unreviewed source site'):
            extract(rows,self.sources)

    def test_literal_null_helper_record_cannot_replace_microsoft_setter_read(self):
        rejected=json.loads((ROOT/'rejected-advanced-helper.json').read_text())['row']
        rows=copy.deepcopy(self.rows)
        index=next(index for index,row in enumerate(rows)
                   if row['framework']==rejected['framework']
                   and row['execution']==rejected['execution']
                   and row['testMethodSha256']==rejected['testMethodSha256']
                   and row['sourceSiteSha256']==rejected['sourceSiteSha256'])
        rows[index]=rejected
        self.assertEqual(len(rows),len(self.rows))
        with self.assertRaisesRegex(ValueError,'helper invocation record identity'):
            extract(rows,self.sources)

    def test_shared_explicit_helper_requires_record_pins(self):
        spec=next(s for s in EXTRA_SPECS if s['method'].startswith('CompatibilityAdvancedExtensionQueryComparisonTests.'))
        original=spec.pop('reviewedRecords')
        try:
            with self.assertRaisesRegex(ValueError,'requires reviewed record identities'):
                extract(self.rows,self.sources)
        finally:
            spec['reviewedRecords']=original

    def test_literal_reset_error_control_is_not_a_microsoft_observation(self):
        name='CompatibilityDirectoryResultCursorComparisonTests.Reset_rewinds_cached_results_after_optional_materialization'
        full='AdForLinux.DifferentialTests.'+name
        cls,member=name.split('.')
        rows=copy.deepcopy(self.rows)
        target=next(row for row in rows if row['testMethodSha256']==sha(full))
        target['sourceSiteSha256']=sha('\0'.join([full,cls+'.cs',member,'96','value','explicit-microsoft-comparison']))
        target['microsoftExpectedObservation']={'type':'exception-type','value':'System.InvalidOperationException'}
        with self.assertRaisesRegex(ValueError,'Unreviewed source site'):
            extract(rows,self.sources)

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
