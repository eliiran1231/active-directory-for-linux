"""Source-only checks. Does not launch PowerShell, .NET, tests, or contact AD."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[3]
HELPER = Path(__file__).with_name('Invoke-WorkflowCapture.ps1').read_text()
WORKFLOW = (ROOT / '.github/workflows/differential.yml').read_text()

class WorkflowContract(unittest.TestCase):
    def test_opt_in_default_false(self):
        block = WORKFLOW.split('      record_expected_outputs:', 1)[1].split('      backend:', 1)[0]
        self.assertIn('type: boolean', block)
        self.assertIn('default: false', block)

    def test_inherited_capture_disabled_and_offline_guard_preserved(self):
        for name in ('ADFL_SUITE_CAPTURE_DIRECTORY', 'ADFL_SUITE_CAPTURE_MODE', 'ADFL_SUITE_CAPTURE_REVIEW_FILE'):
            self.assertIn(name + ': ""', WORKFLOW)
        self.assertIn('IsNullOrEmpty($env:ADFL_OFFLINE_TESTS)', WORKFLOW)
        self.assertLess(WORKFLOW.index('Respect the existing offline safety guard'), WORKFLOW.index('Create per-run test OU'))
        self.assertNotIn('ADFL_OFFLINE_TESTS: ""', WORKFLOW)

    def test_raw_upload_excluded_when_recording(self):
        block = WORKFLOW.split('      - name: Upload test results', 1)[1].split('      - name:', 1)[0]
        self.assertIn('!(github.event_name ==', block)
        self.assertIn('inputs.record_expected_outputs)', block)

    def test_ps51_private_output_and_no_replacement_tests(self):
        self.assertIn('#requires -Version 5.1', HELPER)
        self.assertIn('[IO.Directory]::CreateDirectory($Path,$acl)', HELPER)
        self.assertIn('& dotnet test tests/AdForLinux.DifferentialTests', HELPER)
        self.assertNotIn('--filter', HELPER)
        self.assertIn("'tests.stdout.log'", HELPER)
        self.assertIn("'tests.stderr.log'", HELPER)

    def test_system_owner_uses_distinct_allowed_sids(self):
        self.assertIn("@($owner.Value,'S-1-5-18') | Select-Object -Unique", HELPER)
        self.assertIn('$rules.Count -ne $allowedSids.Count', HELPER)
        self.assertNotIn('$rules.Count -ne 2', HELPER)

    def test_complete_envelope_before_export(self):
        self.assertIn('UniqueJsonKeys $line', HELPER)
        self.assertIn("$r.sourceMember -cnotin @('.ctor','.cctor') -and $r.sourceMember -cnotmatch", HELPER)
        self.assertIn("$r.sequence -ne ($sequence+1)", HELPER)
        self.assertIn('$r.observations -ne $sequence', HELPER)
        self.assertLess(HELPER.index('if (-not $valid) {continue}'), HELPER.index("kind='reviewed-scalar-pair'"))

    def test_original_always_cleanup_retained(self):
        block = WORKFLOW.split('      - name: Delete per-run test OU', 1)[1].split('  restricted-linux-kerberos:', 1)[0]
        self.assertIn('always()', block)
        self.assertIn('Remove-ADOrganizationalUnit', block)
        self.assertIn('Invoke-PerRunOuCleanup', block)
        self.assertIn("'ou-cleanup.private.log'", block)

    def test_no_oracle_promotion(self):
        self.assertIn("microsoftOrigin='unverified'", HELPER)
        self.assertIn("theoryInputMapping='unresolved'", HELPER)
        self.assertIn("replayEligibility='unverified'", HELPER)
        self.assertIn("'exception-type'", HELPER)
        self.assertIn('$script:exceptionNames.Contains($value)', HELPER)

if __name__ == '__main__':
    unittest.main()
