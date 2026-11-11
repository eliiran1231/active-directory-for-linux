# Optional workflow scalar logging (prepared, not executed)

`differential.yml` adds a workflow-dispatch boolean `record_expected_outputs`,
default false. Scheduled/default runs retain their original behavior. Nothing
in this preparation dispatches a workflow, accesses AD or publishes a branch.

When explicitly enabled on the Windows job:

1. Keep the existing ad-lab environment approval, secrets, per-run OU, solution
   restore and always-run OU deletion.
2. Create private local fixed-drive output with owner+SYSTEM-only protected ACLs,
   then build the original differential project Release for both Windows targets.
3. Run the same unfiltered project for net10 and net8 with original fixtures and
   assertions, adding the reviewed live scalar collector policy and private review
   JSON. Build/test stdout/stderr, TRX and JSONL stay private on the runner.
4. Print only admitted scalar/finite-exception observations through the helper.
   Both equal and unequal pairs are printed. Original test exit failures still
   fail the workflow. Raw artifact upload is disabled only for recording runs.
5. Preserve the original workflow's net8 attempt even after net10 test failure.
   Unlike the separate manual first-capture wrapper, this integration deliberately
   retains that existing lifecycle. Fixture cleanup is best effort and not proven
   by test success; the existing always-run outer OU cleanup remains essential.

This uses Windows PowerShell 5.1 and .NET Framework APIs, not the unverified
PowerShell 7.4 prerequisite of the separate manual wrapper. It still requires an
already configured Windows runner with SDK/test runtime for both original targets,
Git, existing certificate trust, AD module, lab credentials and approved AD scope.
No installation, security-setting change, new runner or provisioning is added.

## Public log policy

Allowed: null, booleans, integral numeric/enum observations and a finite exact
exception-name allowlist already used by SuiteCapture. Other strings, identifiers,
DNs, hostnames, credentials, bytes, objects and exception messages are never
forwarded. Integers parsed as non-integral CLR types by PowerShell 5.1 are withheld,
not rounded. Invalid/incomplete execution files produce counters, not raw lines.

`reviewed-scalar-pair` labels explicit Microsoft/ours observations and reports
`observedScalarsEqual`; that is not proof of the original assertion's outcome or
semantics. `unverified-assertion-operand` explicitly has unverified Microsoft
origin and must never be promoted to a Microsoft oracle. All replay eligibility
remains unverified. A sourceSiteSha256 identifier hashes only code metadata:
testMethod, sourceFile, sourceMember, sourceLine, role and origin, joined with NUL.
It never hashes observed values. The summary includes reviewed source/assembly
hashes. Each row also includes the opaque execution GUID, source commit and a hash of the
validated test method identity, so repeated invocations can be grouped without
raw theory arguments. Source metadata shape and allowed role tokens are checked
before hashing. These IDs aid later source reconciliation, but mapping each
theory execution to its input row remains explicitly unresolved. A method-level
BeforeAfter hook does not provide broad exact TRX row joins. Matching/mismatching
candidate labels describe only the admitted snapshots, not original test verdicts. Redacted/unsupported, malformed and incomplete counts are
shown. No static or capture count is claimed as runtime coverage.

The policy broadens numeric/bool/enum capture beyond detached sites to the
already-evaluated live lab values. Enabling it requires review of that privacy
scope: numeric directory state can be sensitive too. Only use a disposable lab
whose scalar state has been approved for these logs. The workflow input is an
explicit per-run opt-in, not permission to publish raw evidence or future runs.

Private raw files remain under the runner's private capture directory after the
job. There is no automatic upload or deletion. The owner must review retention
and remove them through an authorized local process. Same-user processes, SYSTEM
and administrators are trusted. A compromised runner is outside this ACL boundary.
The existing cleanup removes the AD OU, not these private local diagnostics.

## Validation still needed

Neither this helper nor the modified workflow has been executed here. Before live
use, parser-check on Windows PowerShell 5.1 and validate with synthetic JSONL:
matching/mismatching scalar pairs; arbitrary secret-like strings; redacted and
unknown snapshot types; malformed/truncated records; mismatched review hashes;
missing end/review; hostile exception names; large integers; failed test process;
ACL denial/network/reparse output; empty capture. Verify default false and schedule
paths are unchanged and no recording raw files match artifact-upload paths.

A later Linux regression workflow must be a separate deliverable. It needs exact
source-site/test-row reconciliation and reviewed replay eligibility, not blind
conversion of these log records into expected constants.

Offline test sources contain eight static source/workflow checks and thirteen
synthetic Python policy examples. All 21 checks passed in offline validation.
The Python examples demonstrate the required contract, not actual PowerShell
behavior; passing them cannot establish Windows runtime/sanitizer correctness.

The job explicitly clears inherited capture directory/mode/review variables.
Source pins exist only inside the cleared review-file pointer, not a separate
collector environment variable. An existing ADFL_OFFLINE_TESTS guard blocks the
workflow before OU creation; it is never cleared or overridden.

ACL admission uses distinct owner/SYSTEM SIDs, supporting a LocalSystem runner
with one protected FullControl ACE rather than requiring a duplicate SYSTEM ACE.
