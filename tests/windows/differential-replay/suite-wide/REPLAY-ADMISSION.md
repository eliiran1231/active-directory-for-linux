# Suite capture to Linux replay: admission plan

## Current boundary

Suite-wide instrumentation is an observation and coverage aid, not a portable
oracle. The standalone `detached.py` wrapper runs only eight explicitly pinned
methods in three reviewed detached classes. Its 80 exact theory names come from
`detached-cases.json`, copied from the prior reviewed case-name contract **without
copying observation values**. Editing the numeric privacy manifest cannot expand
execution admission.

The private package is always `unvalidated-not-replayable` with `oracleAdmission:
none`. A successful package proves the wrapper validated its stated evidence:
80 passing named rows, one marker per row, one capture per marker, intact records,
consistent Windows/runtime/assembly/source metadata, and at least one explicit
non-redacted Microsoft candidate per case. These are consistency checks, not a
cryptographic attestation of the Windows host or a replay compatibility claim.
No new fresh Windows capture, portable expected values, or Linux replay coverage
is asserted merely because the Python checks pass.

## Run the bounded detached capture

Prerequisites: Windows, Python 3.10+, the requested .NET SDK/runtime, dependencies
already restored for the original project, and the reviewed branch committed
with no tracked changes or untracked inputs. The operator must create a local
private directory **outside the checkout**, restrict its Windows ACL to authorized
accounts, and use a private checkout/build location too. The wrapper does not
create or inspect ACL grants and does not silently restore packages.

A source-only check works on Linux and runs no test process:

```text
python tests/windows/differential-replay/suite-wide/detached.py --check-only
```

A real run, from the committed checkout on Windows:

```text
python tests/windows/differential-replay/suite-wide/detached.py --framework net8.0-windows --private-directory C:\Private\AdflCapture --output C:\Private\AdflCapture\detached-net8.json --private-acl-confirmed --source-commit <full-40-character-HEAD>
```

Repeat separately with `net10.0-windows` and a new output filename. These are two
separate captures and two provenance envelopes, not interchangeable or merged
expected values. `--source-commit` is optional, but when supplied must exactly
match HEAD. The wrapper independently records/checks HEAD either way and supplies that
verified hash as the fixed MSBuild `SourceRevisionId`, with revision inclusion
enabled. It still refuses captures whose embedded commit does not match. A normal
run refuses non-Windows. `--check-only` validates manifests and hashes but does
not promise SDK availability or a clean checkout unless `--source-commit` is also
specified.

The subprocess is the original differential project, Release, the selected
Windows framework, `--no-restore`, and an OR of eight exact
`FullyQualifiedName=...` expressions. No class/substring filters, additional
arguments, `--no-build`, live-directory filters, upload, or workflow modification
are exposed. Ordinary builds still use the checkout's normal `bin`/`obj` paths.

The parent environment is never mutated. The child inherits normal build
settings with every case-insensitive `AD_*` and `ADFL_*` key removed **before its
value is read**, then receives only these two instrumentation settings:
`ADFL_OFFLINE_TESTS=1` and `ADFL_SUITE_CAPTURE_DIRECTORY=<fresh-private-subdir>`.
This guard/filter is defense in depth, not a general network sandbox. It does not
authorize live AD, privileged credentials, or expanding the selected methods.

Every run gets fresh capture and TRX directories. Raw JSONL, TRX, and build/test
stdout/stderr are deleted after validation, ordinary failure, and cancellation
whose termination-helper success/root exit are confirmed. There is no elective
raw-retention option. On cancellation the wrapper attempts the system
`taskkill /T /F`, checks its exit code, and limits that subprocess to 10 seconds.
A root-exit wait after helper success is limited to 10 seconds; root-only fallback
has a 5-second wait and never establishes descendant termination. This is
best-effort cancellation, not a kernel job-object guarantee. Helper failure,
helper timeout, interrupted termination or unconfirmed root exit fails closed:
no package is produced and the workspace remains private for operator process
inspection before removal. No unbounded wait or false root-only success is used.
The sanitized package is written only after raw cleanup
succeeds, with exclusive creation and no overwriting. Only counts/status are
printed. A filesystem cleanup failure fails closed before package publication;
the operator must remove any leftovers within the supplied private directory.
No program can guarantee cleanup after machine termination or storage failure.
Do not attach or commit the private package as if it were an admitted fixture.

## Deterministic identities and evidence

- `case-v1`: SHA-256 of the exact reviewed case name, encoded as the documented
  compact JSON array by `stable_id`. Case names are synthetic reviewed inputs,
  not harvested live directory identifiers.
- `site-v1`: SHA-256 of test method, source basename, source member, source line,
  and comparison role. This is stable within the source contract. Source line
  changes deliberately change the site identity; do not silently align shifted
  sites across revisions.
- `observation-v1`: SHA-256 of case ID, site ID, and the 1-based occurrence of
  that site in the case. Repeated helper calls remain distinct. Original source
  sequence is retained to review step ordering.
- Each package binds source hashes, the full source commit, both manifest hashes,
  target/runtime/SDK, Windows/architecture, Microsoft assembly versions, and the
  test assembly hash. A fresh run must match its built test DLL and TRX codebase.
- Random capture IDs, TRX test/execution GUIDs, timestamps, absolute paths,
  arbitrary stdout, and clone snapshots are excluded. Cases are sorted and JSON
  keys are sorted. Identical validated evidence produces identical package bytes
  despite execution ordering or random marker IDs.
- Every raw record, including discarded clone snapshots and unverified assertion
  operands, passes `collect.load` first. Only `explicit-microsoft-comparison`
  snapshots become package observations. Unverified assertion operands are
  counted but never promoted into expected Microsoft results.

Do not use a source line hash as a timeless semantic operation ID. Admission
requires a reviewed mapping from these source identities to versioned semantic
operations before cross-revision fixtures are compared.

## First admission batches: reuse operations, not thousands of custom tests

Start with these three families and eight operation templates. The counts below
are the reviewed *input row counts*, not newly observed successful executions.

| Family | Operation templates | Rows | Portable scalar candidates | Intentionally opaque today |
|---|---|---:|---|---|
| Searcher state | timeout boundary/rejection/recovery; coupled option state transitions | 33 + 6 = 39 | timeout ticks, numeric search scope/page size, cache/VLV/sync identity booleans, known exception types/null | attribute strings and exception parameter strings |
| Synchronization state | full-width option constructors/setter; copy isolation; reset/buffer isolation | 12 + 4 + 4 = 20 | full-width option integer, creation/identity booleans, known exception types/null | cookie contents and parameter strings |
| Virtual-list-view state | total/percentage/offset transitions; rejected setter/recovery; target/context transitions | 10 + 8 + 3 = 21 | counts/offset/percentage, context identity/null booleans, known exception types/null | target strings and parameter strings |

For each family, add **one reusable operation interpreter** with a finite command
vocabulary (construct, set reviewed property, read reviewed scalar, copy/reset,
observe approved exception type). Preserve the existing tests' exact construction,
mutation, observation order, and integer widths. Theory rows become data, not a
new bespoke handwritten C# test per observation. The reviewed mapping names each
step and observation, defines argument types and comparison semantics, and pins
the original source site plus its occurrence. Never infer semantic labels from
private output or from clone values.

A subsequent operation contract should contain:

```text
familyId, operationVersion, caseId, reviewedInputs,
orderedSteps, observationId -> semanticObservationId,
expectedType, comparisonSemantics, sourceContractHash
```

`reviewedInputs` must be transcribed from the reviewed synthetic test sources,
including signed/unsigned widths and deliberate boundary constants. The case name
is an identity check, not an executable expression or a general argument parser.
Do not evaluate C# or infer inputs by parsing arbitrary display strings.

## Per-family gates, in order

1. **Fresh Microsoft evidence.** Run the wrapper from the exact reviewed commit
   on Windows for each supported framework. Resolve every missing, extra,
   duplicate, failed, skipped, unlinked, truncated, mixed-provenance, or all-opaque
   case first. Never backfill old observations, expected values, or clone values.
2. **Source-to-operation review.** Review one family mapping and its finite
   interpreter against the original methods. Check call/step order, exception
   unwrapping, conditional branches, integer width, property selection, and each
   repeated helper occurrence. Include explicit coverage of mutation recovery.
3. **Microsoft-only projection.** Select only snapshots with approved scalar
   types from explicit Microsoft comparison origins. `replayable` in raw snapshots
   means only a supported scalar *shape*. It is not fixture admission. A redacted
   string, byte array, object, unknown type, or unverified assertion operand has no
   expected value and cannot become `null`, an empty value, or a guessed scalar.
4. **Determinism check.** Repeat fresh Windows capture for that family contract
   and framework, compare by semantic observation ID, and inspect any difference.
   Do not silently majority-vote inconsistent values. Version/review any legitimate
   platform/runtime split. Keep framework-specific expectations when needed.
5. **Linux replay proof.** Run the same interpreter with only the clone on Linux,
   with network/directory access disabled and no Microsoft runtime available.
   The interpreter executes reviewed inputs and compares against the admitted
   Microsoft scalar projection. Add tests that intentionally perturb a scalar,
   exception type, row ID, width, step ordering, and missing observation to prove
   mismatches cannot accidentally pass.
6. **Explicit admission.** Produce a separately reviewed fixture schema containing
   the semantic contract, private-source provenance digest, scalar expected values,
   framework/platform scope, and the reviewer-approved admission version. Only
   this separate promotion may change status to admitted. The capture wrapper
   must never perform that promotion or write directly into existing oracle files.
7. **Coverage report.** Report original input rows, original observation count,
   scalar admitted observation count, opaque/unverified excluded count, fully
   replayed rows, partially replayed rows, and rejected rows. A scalar-only
   projection of a row with opaque cookie/target checks is **partial row coverage**,
   not proof that the whole original row or family replays on Linux.

Opaque observations remain explicit `unsupported` entries in admission reports.
Strict promotion fails if a requested full row includes unsupported observations.
An explicitly selected partial projection may skip those observations, but the
skip must appear in machine-readable output and cannot be included in the pass
count. This policy applies even if every included scalar agrees with the clone.

## Extending to the suite

Use the static inventory to partition by operation family and dependence:

1. Detached constructors, setters, primitive projections, enum and exception
   validation: first candidates for new reviewed finite operation contracts.
2. Synthetic object graphs and in-memory lifecycle/state machines: admit after
   isolation and provenance review, reusing family interpreters where semantics
   match rather than coalescing tests by similar names.
3. Directory-bound reads, authentication, searches, live objects, opaque identity,
   environment-dependent exceptions, or writes: remain excluded from this runner.
   They require a separate approved synthetic environment and fixture policy,
   not a wider substring filter or reclassification of captured scalars.

Add new independently reviewed family contracts and row-name admission sets in
small batches. Update source hashes and source-to-semantic mappings together.
Keep privacy admission, execution admission, semantic admission, and coverage
counts separate. Hundreds of instrumented files or thousands of scalar-shaped
observations are not evidence of whole-suite replay.

## Verification available now

`python -m unittest discover -s tests/windows/differential-replay/suite-wide -p 'test_*.py'`
checks manifests/instrumentation and mocked detached capture fixtures. The
runner tests exercise exact selection, changed sources, case/marker bijection,
TRX integrity, raw-record strictness, framework/assembly/commit consistency,
Microsoft-only projection, deterministic identities, environment isolation,
private-path rejection, and success/failure/timeout cleanup. They deliberately
run no dotnet test, no live AD, and no fresh Microsoft capture. Actual Windows
SDK compilation, adapter TRX formatting, and two-framework execution still need
the bounded real smoke above before any fresh-capture claim.
