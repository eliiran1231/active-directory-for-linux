import copy
import json
import pathlib
import unittest
from unittest import mock
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
            self.assertEqual(len(methods),51)
            self.assertEqual(sum(map(len,methods.values())),174)
            self.assertEqual(sum(len(sequence.split(',')) for rows in methods.values() for sequence in rows),529)

    def test_expiration_raw_and_typed_ticks_are_lossless_and_source_pinned(self):
        method='CompatibilityExpirationPersistenceComparisonTests.Expiration_Save_conversion_and_fresh_reload_match_microsoft'
        spec=next(s for s in SPECS if s['method']==method)
        self.assertEqual(spec['maxOccurrences']['131'],2)
        self.assertEqual(spec['maxOccurrences']['132'],2)
        self.assertEqual(spec['enumDomains']['132'],{'type':'System.DateTimeKind','values':[0,1,2]})
        oracle=extract(self.rows,self.sources)
        for methods in oracle['frameworks'].values():
            self.assertEqual(len(methods[method]),3)
            for sequence in methods[method]:
                self.assertIn('78=i64:135510212960001234',sequence)
                self.assertEqual(sequence.count('131=i64:640421444960001234'),2)

    def test_lastlogon_int64_is_exact_and_rejects_aliases_and_overflow(self):
        target=next(i for i,row in enumerate(self.rows) if row.get('microsoftExpectedObservation',{}).get('type')=='int64')
        for bad in (True,False,1.0,'1',2**63,-2**63-1):
            rows=copy.deepcopy(self.rows);rows[target]['microsoftExpectedObservation']['value']=bad
            with self.subTest(value=bad),self.assertRaisesRegex(ValueError,'Invalid Int64'):
                extract(rows,self.sources)
        rows=copy.deepcopy(self.rows);rows[target]['microsoftExpectedObservation']['value']=2**53+1
        oracle=extract(rows,self.sources)
        self.assertTrue(any('i64:9007199254740993' in sequence for methods in oracle['frameworks'].values() for values in methods.values() for sequence in values))

    def test_enum_domains_cannot_be_swapped_between_date_and_nullability_sites(self):
        specs=copy.deepcopy(SPECS)
        for spec in specs:
            for domain in spec.get('enumDomains',{}).values():
                domain['type']='System.DateTimeKind' if domain['type']=='System.Reflection.NullabilityState' else 'System.Reflection.NullabilityState'
        with mock.patch('extract_reviewed_assertions.SPECS',specs):
            with self.assertRaisesRegex(ValueError,'Unreviewed enum domain'):
                extract(self.rows,self.sources)

    def test_names_only_clone_counts_and_literal_zeros_are_rejected(self):
        rejected=json.loads((ROOT/'rejected-names-only-operands.json').read_text())['rows']
        self.assertEqual(len(rejected),22)
        for replacement in rejected:
            rows=copy.deepcopy(self.rows)
            index=next(i for i,row in enumerate(rows) if row['framework']==replacement['framework']
                and row['testMethodSha256']==replacement['testMethodSha256'])
            rows[index]=replacement
            with self.subTest(record=replacement['record']),self.assertRaisesRegex(ValueError,'operand role|helper invocation record identity'):
                extract(rows,self.sources)

    def test_rename_mode_formula_is_not_microsoft_wrapper_evidence(self):
        spec=next(s for s in SPECS if s['method']=='CompatibilityRenameRetainedCacheComparisonTests.Rename_retains_or_replaces_managed_cache_like_microsoft')
        full='AdForLinux.DifferentialTests.'+spec['method']
        rows=copy.deepcopy(self.rows)
        target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
        target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],'78','assert-equal-expected','assertion-operand-unverified']))
        with self.assertRaisesRegex(ValueError,'operand role'): extract(rows,self.sources)

    def test_implicit_cache_mode_literals_are_not_wrapper_observations(self):
        spec=next(s for s in SPECS if s['method']=='CompatibilityImplicitWriteCacheComparisonTests.Scalar_write_replaces_managed_cache_at_the_same_commit_boundary')
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line in (62,63):
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),'assert-equal-expected','assertion-operand-unverified']))
            with self.subTest(line=line), self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_persisted_uac_literals_and_clone_flags_are_rejected(self):
        spec=next(s for s in SPECS if s['method']=='CompatibilityAccountControlMergeComparisonTests.Staged_account_flag_merges_with_native_entry_changes')
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(69,'assert-equal-expected'),(70,'assert-equal-actual'),
                          (79,'assert-equal-expected'),(80,'assert-equal-actual'),
                          (86,'assert-equal-expected'),(89,'assert-equal-expected'),
                          (90,'assert-equal-actual'),(91,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role), self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_account_literal_and_clone_read_are_not_microsoft_evidence(self):
        spec=next(s for s in SPECS if s['method']=='UnsavedAccountStateComparisonTests.Setting_an_account_flag_preserves_unassigned_enabled_state')
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(65,'assert-equal-expected'),(66,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full))
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role), self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_enum_payloads_reject_aliases_bounds_and_unknown_domain_values(self):
        for value in (False,True,-1,3,2**63,-2**63-1,2.0,'2'):
            rows=copy.deepcopy(self.rows)
            target=next(row for row in rows if row['operand']['type']=='enum-int64')
            target['operand']['value']=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'enum'):
                extract(rows,self.sources)

    def test_enum_domain_must_be_explicitly_reviewed(self):
        spec=next(s for s in SPECS if s['method']=='DirectoryEntryRenameComparisonTests.Rename_parameter_nullability_matches_microsoft')
        with mock.patch.dict(spec['enumDomains'],{},clear=True):
            with self.assertRaisesRegex(ValueError,'Unreviewed enum domain'):
                extract(self.rows,self.sources)

    def test_default_options_literal_control_is_not_an_oracle_site(self):
        spec=next(s for s in SPECS if s['method']=='UserPrincipalComparisonTests.PrincipalContext_default_domain_options_agree')
        full='AdForLinux.DifferentialTests.'+spec['method']
        rows=copy.deepcopy(self.rows)
        target=next(row for row in rows if row['testMethodSha256']==sha(full))
        target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],'419','assert-equal-expected','assertion-operand-unverified']))
        with self.assertRaisesRegex(ValueError,'operand role'):
            extract(rows,self.sources)

    def test_complete_metadata_scope_requires_explicit_narrow_review(self):
        spec=next(s for s in SPECS if s['method']=='DirectoryEntryRenameComparisonTests.Rename_parameter_nullability_matches_microsoft')
        for change in ({'coverage':'complete-all-behavior'},{'completionReview':''},
                       {'adaptation':'omitted fixture phase'},{'kind':'Theory'},
                       {'inputProjection':{'excludedInputs':['uncovered']}}):
            with self.subTest(change=change),mock.patch.dict(spec,change):
                with self.assertRaises(ValueError):
                    extract(self.rows,self.sources)
        self.assertEqual(extract(self.rows,self.sources)['completeMetadataFacts'],[spec['method']])

    def test_clone_only_helper_record_cannot_replace_an_admitted_microsoft_read(self):
        rejected=json.loads((ROOT/'rejected-serialization-helper.json').read_text())['row']
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

    def test_shared_helper_record_pins_are_mandatory(self):
        spec=next(s for s in SPECS if s['method'].startswith('CompatibilityExceptionSerializationComparisonTests.'))
        original=spec.pop('reviewedRecords')
        try:
            with self.assertRaisesRegex(ValueError,'requires reviewed record identities'):
                extract(self.rows,self.sources)
        finally:
            spec['reviewedRecords']=original

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

    def test_clone_only_fourth_serialization_helper_call_rejected(self):
        spec=next(s for s in SPECS if s['method'].startswith('CompatibilityExceptionSerializationComparisonTests.'))
        full='AdForLinux.DifferentialTests.'+spec['method']
        site=sha('\0'.join([full,spec['file'],'AssertMetadata','86','assert-equal-expected','assertion-operand-unverified']))
        rows=copy.deepcopy(self.rows)
        extra=copy.deepcopy(next(r for r in rows if r['testMethodSha256']==sha(full) and r['sourceSiteSha256']==site))
        extra['record']=max(r['record'] for r in rows)+1
        rows.append(extra)
        with self.assertRaisesRegex(ValueError,'Unreviewed helper invocation'):
            extract(rows,self.sources)

    def test_microsoft_read_in_actual_slot_does_not_admit_literal_slot(self):
        spec=next(s for s in SPECS if s['method']=='PrincipalSearchResultPositionComparisonTests.Empty_result_Current_matches_position_validation')
        full='AdForLinux.DifferentialTests.'+spec['method']
        rows=copy.deepcopy(self.rows)
        target=next(r for r in rows if r['testMethodSha256']==sha(full))
        target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],'41','assert-equal-expected','assertion-operand-unverified']))
        with self.assertRaisesRegex(ValueError,'operand role'):
            extract(rows,self.sources)

    def test_live_cursor_literal_type_and_clone_tuple_are_not_microsoft_evidence(self):
        spec=next(s for s in SPECS if s['method']=='PrincipalSearchResultLivePositionComparisonTests.FindAll_Current_matches_position_validation')
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(66,'assert-equal-expected'),(67,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full))
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role),self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_result_count_literals_and_clone_counts_are_excluded(self):
        spec=next(s for s in SPECS if s['method']=='CompatibilitySearchResultLifecycleComparisonTests.Enumeration_and_materialized_lookup_identity_match_microsoft')
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(35,'assert-equal-expected'),(36,'assert-equal-actual'),(42,'assert-equal-expected'),(43,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full))
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role),self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_mixed_origins_require_review_and_correct_record_kind(self):
        spec=next(s for s in SPECS if s.get('explicitSites'))
        with mock.patch.dict(spec,{'explicitReview':''}):
            with self.assertRaisesRegex(ValueError,'explicit source review'):
                extract(self.rows,self.sources)
        for original,wrong in [('reviewed-scalar-pair','unverified-assertion-operand'),('unverified-assertion-operand','reviewed-scalar-pair')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha('AdForLinux.DifferentialTests.'+spec['method']) and r['kind']==original)
            target['kind']=wrong
            with self.subTest(original=original),self.assertRaisesRegex(ValueError,'reviewed source origin'):
                extract(rows,self.sources)

    def test_mixed_explicit_sites_never_take_clone_payloads(self):
        expected=extract(self.rows,self.sources)
        rows=copy.deepcopy(self.rows)
        for row in rows:
            if row['kind']=='reviewed-scalar-pair':
                row['ourActualObservation']={'type':'int32','value':123}
                row['operand']={'type':'int32','value':456}
        self.assertEqual(extract(rows,self.sources),expected)

    def test_binary_lengths_exclude_literal_and_clone_operand_sites(self):
        spec=next(s for s in SPECS if s.get('explicitSites'))
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(26,'assert-equal-expected'),(44,'assert-equal-expected'),(45,'assert-equal-actual'),(63,'assert-equal-expected'),(64,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role),self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_stored_identity_input_literal_and_clone_read_are_not_evidence(self):
        spec=next(s for s in SPECS if s['method'].startswith('PersistedPrincipalEqualityDisposalComparisonTests.'))
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(46,'assert-equal-expected'),(47,'assert-equal-actual')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role),self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_pending_member_input_literals_and_clone_reads_are_excluded(self):
        spec=next(s for s in SPECS if s['method'].startswith('CompatibilityPendingMemberEqualityComparisonTests.'))
        full='AdForLinux.DifferentialTests.'+spec['method']
        for line,role in [(66,'assert-equal-expected'),(67,'assert-equal-actual'),(68,'assert-equal-expected'),(69,'assert-equal-actual'),(87,'assert-equal-expected')]:
            rows=copy.deepcopy(self.rows)
            target=next(r for r in rows if r['testMethodSha256']==sha(full) and r['kind']=='unverified-assertion-operand')
            target['sourceSiteSha256']=sha('\0'.join([full,spec['file'],spec['method'].split('.')[1],str(line),role,'assertion-operand-unverified']))
            with self.subTest(line=line,role=role),self.assertRaisesRegex(ValueError,'operand role'):
                extract(rows,self.sources)

    def test_reviewed_input_subset_lists_exclusions_without_empty_sequences(self):
        spec=next(s for s in SPECS if s.get('inputProjection'))
        oracle=extract(self.rows,self.sources)
        self.assertEqual(oracle['inputProjections'],{spec['method']:spec['inputProjection']})
        self.assertEqual(spec['inputProjection']['includedInputs'],['Contains','Count'])
        self.assertEqual(spec['inputProjection']['excludedInputs'],['PropertyNames'])
        for methods in oracle['frameworks'].values():
            self.assertEqual(len(methods[spec['method']]),2)
            self.assertTrue(all(methods[spec['method']]))

    def test_input_subset_requires_complete_disjoint_reviewed_scope(self):
        spec=next(s for s in SPECS if s.get('inputProjection'))
        for change in ({'kind':'all-inputs'}, {'sourceDeclaredInputs':True},
                       {'includedInputs':[]}, {'excludedInputs':[]},
                       {'excludedInputs':['Count']}, {'includedInputs':['Contains','Contains']},
                       {'review':''}, {'sourceDeclaredInputs':4}):
            projection=copy.deepcopy(spec['inputProjection']);projection.update(change)
            with self.subTest(change=change),mock.patch.dict(spec,{'inputProjection':projection}):
                with self.assertRaisesRegex(ValueError,'input subset'):
                    extract(self.rows,self.sources)
        for change in ({'kind':'Fact'},{'adaptation':''},{'rows':True}):
            with self.subTest(change=change),mock.patch.dict(spec,change):
                with self.assertRaises(ValueError):
                    extract(self.rows,self.sources)

    def test_input_subset_labels_must_exist_in_pinned_source(self):
        spec=next(s for s in SPECS if s.get('inputProjection'))
        projection=copy.deepcopy(spec['inputProjection'])
        projection['includedInputs'][0]='invented-source-input'
        with mock.patch.dict(spec,{'inputProjection':projection}):
            with self.assertRaisesRegex(ValueError,'labels disagree'):
                extract(self.rows,self.sources)

    def test_fact_execution_count_is_not_a_theory_count(self):
        specs=copy.deepcopy(SPECS)
        fact=next(s for s in specs if s.get('kind')=='Fact')
        fact['rows']=2
        with mock.patch('extract_reviewed_assertions.SPECS',specs):
            with self.assertRaisesRegex(ValueError,'Fact execution count'):
                extract(self.rows,self.sources)

    def test_fixture_keeps_fact_kinds_explicit(self):
        oracle=extract(self.rows,self.sources)
        self.assertEqual(sum(kind=='Fact' for kind in oracle['methodKinds'].values()),13)
        for method,kind in oracle['methodKinds'].items():
            if kind=='Fact':
                for methods in oracle['frameworks'].values():
                    self.assertEqual(len(methods[method]),1)

    def test_public_order_does_not_invent_input_mapping(self):
        self.assertEqual(extract(self.rows,self.sources),extract(list(reversed(self.rows)),self.sources))

if __name__ == '__main__': unittest.main()
