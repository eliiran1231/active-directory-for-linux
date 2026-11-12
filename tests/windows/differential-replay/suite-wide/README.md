# Suite-wide Windows observation capture

This instruments the **existing** differential tests, rather than extending a
list of historical log parsers. No directory operations or production code are
added. It is disabled unless `ADFL_SUITE_CAPTURE_DIRECTORY` is set.

## What is captured

- Every existing `Comparison.Check` and `CheckSet` call is covered centrally.
  Its Microsoft operand is explicitly identified as Microsoft-origin.
- 715 existing `Assert.Equal` sites have identity-preserving wrappers around
  both operands, 1,430 operands total. Wrappers return the same value and static
  type to the original assertion. They do not reevaluate expressions.
- Ten equality sites in the four previously admitted replay source files are
  left byte-for-byte unchanged. Those classes already emit explicit typed
  Microsoft observations. Existing 42-case-per-framework replay is preserved.
- An assembly-level xUnit hook establishes a unique test-body execution ID and
  a private JSONL file. Each observed call has source file, member, line and
  sequence. The same helper or callsite can occur repeatedly within a test.
- All original assertions, exception assertions, setup, cleanup and guards stay
  in place. Non-equality xUnit assertions are not operand-instrumented. The
  inventory records that gap explicitly; it is not full behavioral coverage.

An equality assertion's first operand is **not automatically Microsoft output**.
It may be a literal, an expected constant, or another clone value. Such captures
are labelled `assertion-operand-unverified`. No expression text, property label,
subject or theory argument is recorded. The wrappers are broad observation
coverage, not automatic oracle admission.

## Privacy policy

At unreviewed sites, only null and a finite set of standard exception type
identifiers are admitted. Numeric values, enum values and booleans are also
redacted by default. An explicit privacy-only allowlist admits these scalar
values through 55 exact (test method, source file, source line) tuples at
27 reviewed source lines across eight detached synthetic test methods
in the searcher-state, synchronization and VLV-state classes. The exact sites,
test-method identities and source hashes are in `numeric-sites.json`; this is
not an offline execution allowlist. New sites require review and otherwise fail
closed. Both producer and collector enforce that admission.

Arbitrary strings, arrays/bytes, DateTime objects, GUIDs, SID objects,
collections and other objects are always redacted with `replayable: false`.
Integral projections such as logon timestamps/ticks at other sites are therefore
also redacted. The sink never enumerates an object, calls an observed object's
`ToString`, serializes its properties, or hashes its contents. No site is assumed
to use synthetic data merely because it is a test. Captures must remain private,
and raw live-directory captures are not public fixtures.

Exception messages, connection settings, passwords, credentials, environment
contents, endpoints and real directory identifiers are not capture fields.
Authentication flags and validation outcomes are observations; no authentication
or authorization behavior is changed. Existing test diagnostics/TRX output may
already contain live data independently of this sink. Treat those as private too.

Use an existing private local directory with appropriate Windows ACLs, outside
the checkout and outside shared CI artifact directories. The sink checks an
absolute existing directory and rejects a final symlink/reparse point. It does
not audit inherited ACLs or parent-directory links. Do not automatically upload
these files. This change adds no CI publication or artifact-upload step.

## Detached Windows smoke, without AD

The standalone wrapper selects only the three reviewed detached state families:
eight methods and exactly 80 synthetic theory rows. It verifies source hashes,
uses the offline guard, removes inherited directory settings from the child,
builds current sources, and validates every result/capture binding. No directory
fixture, credential, network configuration, workflow upload or live run is added.
The branch must be committed and clean before executing it.

After building/restoring dependencies on Windows, pre-create a private local
directory outside the checkout with an ACL restricted to authorized accounts:

```powershell
python tests/windows/differential-replay/suite-wide/detached.py --check-only
python tests/windows/differential-replay/suite-wide/detached.py --framework net8.0-windows --private-directory C:\Private\Adfl --output C:\Private\Adfl\detached-net8.json --private-acl-confirmed
python tests/windows/differential-replay/suite-wide/detached.py --framework net10.0-windows --private-directory C:\Private\Adfl --output C:\Private\Adfl\detached-net10.json --private-acl-confirmed
```

`--check-only` works on Linux and executes nothing. Normal execution requires
Windows. Each output must be a new file; existing outputs are never overwritten.
No environment variable is set in the calling shell. Raw captures, TRX and child
process logs live in a fresh temporary directory inside the supplied private
directory. They are deleted after normal completion, ordinary failure, or
cancellation with confirmed termination-helper success. A cleanup failure aborts
package creation without exposing observations.

Cancellation attempts Windows' system `taskkill /T /F` with a 10-second timeout
and checks its exit status. Root-exit waits are bounded (10 seconds after helper
success, 5 seconds for fallback). This is best-effort tree termination, not a
kernel job-object guarantee. If helper success/root exit cannot be confirmed,
root-only fallback never counts as proof: no package is created, raw files stay
only in the existing private workspace, and the CLI requests operator inspection.
Stop/inspect remaining capture processes before removing those private files or
sharing the computer. Machine termination can also prevent automatic cleanup.

The private normalized package is deterministic for the same validated inputs:
case names are sorted, run-specific execution markers are replaced with stable
case/site/occurrence IDs, and only Microsoft-side observations are retained.
All 80 TRX rows must pass and bind one-to-one to capture files using the marker
written through xUnit output at the beginning of each detached test body.
Redacted observations remain redacted. The package is explicitly marked
`unvalidated-not-replayable`; it is not automatically added to Linux replay.
See the [family-level admission plan](REPLAY-ADMISSION.md) for that next step.

No fresh Windows smoke capture has been executed in this development executor.

## Fresh Windows capture

First build the branch and run its normal tooling tests. An SDK is required;
Python validation is not C# compilation.

For the reviewed, detached Windows subset, keep using the guarded runner:

```powershell
# Pre-create this directory and restrict its ACL to your own account.
$env:ADFL_SUITE_CAPTURE_DIRECTORY = 'C:\Private\adfl-capture-net8'
try {
    python tests/windows/run-offline-tests.py surface --framework net8.0 --results-directory C:\Private\adfl-trx-net8
} finally {
    Remove-Item Env:ADFL_SUITE_CAPTURE_DIRECTORY
}
python tests/windows/differential-replay/suite-wide/collect.py C:\Private\adfl-capture-net8
```

Use a fresh directory for each framework/run. Repeat with net10.0 and distinct
capture/results directories. Select additional classes only through the exact
allowlist supported by the runner. This feature does not widen that allowlist.

The whole Windows suite includes live reads and directory mutations. To capture
it, first obtain explicit authorization for the disposable directory, isolated
OU, account/password changes, cleanup and test identity described in the
[differential setup guide](../../AdForLinux.DifferentialTests/README.md).
Then set the capture directory while running the existing authorized live test
command separately for net8.0-windows and net10.0-windows. Do not remove an offline
guard to make an unreviewed test execute, and do not point the suite at production.

No Windows capture or live-directory run was performed to develop this change.

## Validation and completeness

```sh
python tests/windows/differential-replay/suite-wide/inventory.py --output /tmp/suite-inventory.json
python -m unittest discover -s tests/windows/differential-replay/suite-wide -p 'test_*.py'
python -m unittest discover -s tests/windows/differential-replay -p 'test_replay.py'
```

The collector rejects truncated/mismatched/out-of-order JSONL and unreviewed
payload shapes. It reports observation coverage without printing captured values
or generating oracle fixtures. Local JSONL and the enclosing run are not
cryptographically authenticated. Build provenance includes assembly SHA-256,
framework, runtime, SDK, OS/architecture, Microsoft assembly versions and a full
build-embedded source commit when available. The commit is not proof of a clean
worktree; retain an exact source snapshot/patch and a build manifest separately.
Never substitute `GITHUB_SHA` from an unrelated job for build provenance.

The end marker means the xUnit body reached teardown, **not that it passed**.
Assertion failures still produce useful observations; setup/fixture failures may
produce none. Join captures to the separately retained test-run results before
admission. Outside the scoped detached wrapper, theory rows share method names and are
distinguished only by execution ID; no deterministic theory-row identity or
replay key is asserted. The detached wrapper binds only its frozen 80 synthetic
case names through explicit output markers. Other dynamic
MemberData/fixtures require explicit stable row identifiers before replay.
Interrupted runs lack the end marker and are refused. Capture I/O errors fail
visibly rather than silently producing apparently complete evidence.

## Linux execution and replay

The existing `tests/windows/differential-replay/run.py` still runs exactly its admitted
42 cases per framework against the genuine recorded Microsoft expectations.
The four linked source files and their fixture hashes are unchanged.

This broad capture is **not** a replacement Microsoft implementation and does
not make the full original Windows assembly executable on Linux. Many tests
construct Microsoft native objects or require actual directory state before
reaching an assertion. Relabelling clone output as Microsoft, globally aliasing
Microsoft types to the clone, replaying only last assertions, or bypassing the
offline guard would produce misleading coverage.

Use the inventory to group the remaining work at class/operation-family scale:

1. Detached operations: extract shared exercise/observation functions, assign
   stable explicit row/step IDs, capture their original Microsoft branch on
   Windows, and execute only the portable branch against those expectations on
   Linux. Preserve original assertions and source-hash admission.
2. Synthetic strings, collections and binary controls: add narrowly reviewed
   projections and deterministic fixture data. The broad sink intentionally
   does not admit these opaque values automatically.
3. Live operations: run the Linux branch against an explicitly authorized,
   isolated disposable directory. Normalize generated DNs/GUIDs/SIDs, server
   timestamps, ordering and environment-dependent failures through explicit
   fixture roles, not broad string replacement. Cross-controller, authorization
   and server-policy behavior still need actual relevant environments.
4. Admit fresh cases only after checking source/assembly provenance, test-row
   identity, completed run/results, privacy, stable semantics and intentional
   portability boundaries. Keep failed clone cases as failures; do not repair
   recorded Microsoft values to make Linux pass.

No new suite-wide Linux behavioral coverage is claimed by this instrumentation.
See [INVENTORY.md](INVENTORY.md) for source counts and classifications.
