import json
import pathlib
import unittest
from unittest.mock import patch
from coverage_inventory import build, mirror_methods, review_notes, complete_metadata_methods

ROOT=pathlib.Path(__file__).parent

class CoverageLedgerTests(unittest.TestCase):
    def test_reproduces_full_ledger_with_distinct_methods(self):
        ledger=build()
        self.assertEqual(ledger,json.loads((ROOT/'coverage-inventory.json').read_text()))
        self.assertEqual(ledger['summary']['sourceDeclarations'],359)
        self.assertEqual(ledger['summary']['distinctPartiallyMirroredMethods'],149)
        self.assertEqual(ledger['summary']['fullyMirroredMethods'],1)
        self.assertEqual(ledger['summary']['fullyMirroredMetadataFacts'],1)
        self.assertEqual(ledger['summary']['distinctMirroredMethods'],150)
        complete=[m for m in ledger['methods'] if m['status']=='complete_metadata_fact']
        self.assertEqual([m['id'] for m in complete],['AdForLinux.DifferentialTests.DirectoryEntryRenameComparisonTests.Rename_parameter_nullability_matches_microsoft'])
        self.assertTrue(complete[0]['completionReview'])
        self.assertEqual(ledger['summary']['partiallyMirroredFacts'],52)
        self.assertEqual(ledger['summary']['partiallyMirroredTheories'],97)
        self.assertEqual(ledger['summary']['notMirroredMethods'],209)
        self.assertFalse(ledger['summary']['allCasesCovered'])
        self.assertEqual(ledger['summary']['notMirroredPublicEvidence'],{'no_public_scalars':132,'explicit_pair_present':44,'unverified_operands_only':33})
        self.assertEqual(sum(ledger['summary']['notMirroredPublicEvidence'].values()),ledger['summary']['notMirroredMethods'])
        self.assertEqual(sum(ledger['summary']['notMirroredSourceReviews'].values()),ledger['summary']['notMirroredMethods'])
        self.assertEqual(ledger['summary']['historicalSourceLinkedMethods'],8)
        self.assertEqual(ledger['summary']['historicalRecordedCasesPerRuntime'],42)
        self.assertEqual(ledger['summary']['sourceDeclarationsWithAnyRecordedAdapter'],158)
        self.assertEqual(ledger['summary']['sourceDeclarationsWithoutRecordedAdapter'],201)
        adapted=[m for m in ledger['methods'] if m.get('adaptationNote')]
        self.assertEqual(len(adapted),84)
        self.assertTrue(all(m['status']=='partial_recorded_mirror' for m in adapted))
        mirrored=mirror_methods()
        overlap=[name for name,groups in mirrored.items() if 'structured-four-fact-oracle' in groups and 'hardcoded-source-reviewed-operands' in groups]
        self.assertEqual(len(overlap),2)

    def test_blocked_reviews_are_explicit_and_do_not_count_as_passes(self):
        reviewed=[m for m in build()['methods'] if 'sourceReview' in m]
        self.assertEqual(len(reviewed),19)
        for method in reviewed:
            note=method['sourceReview']
            self.assertEqual(method['status'],'not_mirrored')
            self.assertFalse(method['adapters'])
            for metadata in method['public_scalar_metadata'].values():
                self.assertEqual(metadata['observedExecutionIdentitiesWithPublicScalars'],note['observedPublicExecutionsPerRuntime'])
            if note['decision']=='incomplete-public-execution-projection':
                self.assertEqual(method['inline_data_declarations'],note['sourceDeclaredInputs'])
                self.assertLess(note['observedPublicExecutionsPerRuntime'],note['sourceDeclaredInputs'])
            self.assertTrue(note['nextEvidenceNeeded'])

    def test_setup_counts_do_not_claim_copy_or_disposal_outcomes(self):
        # These source-pinned reviews explicitly distinguish setup observations.
        methods=[m for m in build()['methods'] if m.get('sourceReview',{}).get('decision')=='no-public-operation-outcome']
        self.assertEqual(len(methods),2)
        for method in methods:
            self.assertEqual(method['status'],'not_mirrored')
            for metadata in method['public_scalar_metadata'].values():
                self.assertEqual(set(metadata['types']),{'int32'})
                self.assertEqual(set(metadata['kinds']),{'unverified-assertion-operand'})
            self.assertIn('Count',method['sourceReview']['reason'])

    def test_typed_value_reviews_do_not_promote_collection_lengths(self):
        methods=[m for m in build()['methods'] if m.get('sourceReview',{}).get('decision')=='typed-value-projection-missing']
        self.assertEqual(len(methods),2)
        for method in methods:
            self.assertEqual(method['status'],'not_mirrored')
            self.assertFalse(method['adapters'])
            self.assertIn('count-only',method['sourceReview']['nextEvidenceNeeded'])
            for metadata in method['public_scalar_metadata'].values():
                self.assertEqual(set(metadata['types']),{'int32'})
                self.assertEqual(set(metadata['kinds']),{'unverified-assertion-operand'})

    def test_saved_new_cache_reviews_do_not_substitute_found_principals(self):
        reviews=review_notes()
        names=[name for name in reviews if name.startswith((
            'CompatibilityCachedLogonProjectionComparisonTests.',
            'CompatibilityCachedScalarLifecycleComparisonTests.',
            'UserScalarCacheRetentionComparisonTests.'))]
        self.assertEqual(len(names),2)
        for name in names:
            note=reviews[name]
            self.assertEqual(note['decision'],'projected-cache-value-evidence-missing')
            self.assertIn('AttachExisting',note['reason'])
            self.assertIn('SaveCore',note['reason'])
            self.assertIn('input identities',note['nextEvidenceNeeded'])
        retained=reviews['UserScalarCacheRetentionComparisonTests.Loaded_scalar_retains_its_value_after_raw_cache_edits']
        self.assertEqual(retained['sourceDeclaredInputs'],28)
        self.assertEqual(retained['observedPublicExecutionsPerRuntime'],14)

    def test_staged_principal_review_does_not_promote_setup_null_to_retention(self):
        method=next(m for m in build()['methods'] if m['id'].endswith('.Staged_principal_scalar_is_independent_of_entry_cache_and_refresh'))
        self.assertEqual(method['status'],'not_mirrored')
        self.assertFalse(method['adapters'])
        review=method['sourceReview']
        self.assertEqual(review['sourceDeclaredInputs'],2)
        self.assertEqual(review['observedPublicExecutionsPerRuntime'],2)
        self.assertEqual(review['decision'],'projected-cache-value-evidence-missing')
        self.assertIn('raw entry before Save',review['reason'])
        self.assertIn('explicit input identities',review['nextEvidenceNeeded'])

    def test_input_subset_is_explicit_and_source_declarations_are_checked(self):
        ledger=build()
        self.assertEqual(ledger['summary']['methodsWithReviewedInputSubsets'],1)
        self.assertEqual(ledger['summary']['explicitlyExcludedSourceInputs'],1)
        subset=next(m for m in ledger['methods'] if m.get('inputProjection'))
        self.assertEqual(subset['status'],'partial_recorded_mirror')
        self.assertEqual(subset['inline_data_declarations'],3)
        self.assertEqual(subset['inputProjection']['excludedInputs'],['PropertyNames'])
        self.assertFalse(ledger['summary']['allCasesCovered'])

    def test_subset_scope_cannot_be_removed_to_hide_missing_source_inputs(self):
        original=json.loads
        def remove(text,*args,**kwargs):
            value=original(text,*args,**kwargs)
            if isinstance(value,list):
                for spec in value:
                    if isinstance(spec,dict): spec.pop('inputProjection',None)
            return value
        with patch('coverage_inventory.json.loads',side_effect=remove):
            with self.assertRaisesRegex(ValueError,'subset metadata required'):
                build()

    def test_subset_declared_total_must_match_pinned_source(self):
        original=json.loads
        def alter(text,*args,**kwargs):
            value=original(text,*args,**kwargs)
            if isinstance(value,list):
                for spec in value:
                    if isinstance(spec,dict) and spec.get('inputProjection'):
                        spec['inputProjection']['sourceDeclaredInputs']=4
                        spec['inputProjection']['excludedInputs'].append('invented-branch')
            return value
        with patch('coverage_inventory.json.loads',side_effect=alter):
            with self.assertRaisesRegex(ValueError,'source inputs|source declarations'):
                build()

    def test_stale_review_source_is_rejected(self):
        with patch('pathlib.Path.read_bytes',return_value=b'changed source'):
            with self.assertRaisesRegex(ValueError,'Reviewed source changed'):
                review_notes()

    def test_stale_transitive_fixture_review_is_rejected(self):
        original=pathlib.Path.read_bytes
        helper='CompatibilityCachedLogonProjectionComparisonTests.cs'
        def changed(path):
            return b'changed shared helper' if path.name==helper else original(path)
        with patch('pathlib.Path.read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'Reviewed source changed: '+helper):
                review_notes()

    def test_backend_validation_review_pins_the_implementation(self):
        original=pathlib.Path.read_bytes
        def changed(path):
            return b'changed filter preflight' if path.name=='DirectorySearcher.cs' else original(path)
        with patch('pathlib.Path.read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'Reviewed implementation source changed'):
                review_notes()

    def test_implementation_review_paths_cannot_escape_source_tree(self):
        original=json.loads
        for invalid in ('../outside.cs','/tmp/outside.cs','tests/outside.cs','src/../outside.cs'):
            def alter(text,*args,**kwargs):
                value=original(text,*args,**kwargs)
                if isinstance(value,dict) and 'notes' in value:
                    note=next(n for n in value['notes'] if n.get('relatedImplementationSources'))
                    note['relatedImplementationSources'][0]['file']=invalid
                return value
            with self.subTest(path=invalid),patch('coverage_inventory.json.loads',side_effect=alter):
                with self.assertRaisesRegex(ValueError,'implementation source path'):
                    review_notes()

    def test_completed_metadata_source_pin_cannot_go_stale(self):
        original=pathlib.Path.read_bytes
        def changed(path):
            return b'changed metadata assertion' if path.name=='DirectoryEntryRenameComparisonTests.cs' else original(path)
        with patch('pathlib.Path.read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'Completed metadata source changed'):
                complete_metadata_methods()

if __name__=='__main__': unittest.main()
