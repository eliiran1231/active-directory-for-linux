# Recorded differential replay prototype

This pilot reuses the **same theory declarations, inputs, exercise methods and
assertions** as four existing Windows differential classes. The portable project
links those source files rather than creating a second behavioral suite. Only
Microsoft object construction and the expected-observation provider change under
`RECORDED_MICROSOFT_ORACLE`. The normal Windows build still executes Microsoft
and AdForLinux side by side.

## Scope

- `PrincipalValueCollectionTraversalAndCopyComparisonTests`: 18 rows covering
  generic/non-generic Current after count changes and CopyTo destination bounds.
- `ResultValueEnumeratorComparisonTests`: 12 rows covering concrete/interface
  Current position validation and Reset traversal.
- `PrincipalValueCollectionCopyFailureComparisonTests`: 8 rows covering covariant
  partial writes, incompatible array element types and multidimensional arrays.
- `GroupConstructorValidationComparisonTests`: 4 rows covering null-context
  overload validation, including null, empty and ordinary names.
- 42 rows per framework, independently recorded for net8.0 and net10.0.

All selected cases are detached in-memory operations. The project explicitly
compiles only these four classes and the recording loader. It has no Microsoft
DirectoryServices package reference, fixture provisioning, directory settings,
Windows assembly execution, native worker or live AD requirement. Its assembly
name preserves the existing differential friend-assembly boundary for the normal
result-collection constructor; production access declarations are unchanged.

This is partial coverage, not a replacement for live differential tests or the
functional suite. Run #202 logs do not record every assertion or intermediate
state, and many other differential tests record nothing reusable. Live writes,
authentication, schema, permissions, caching and persisted server state cannot
be replayed faithfully just from an expected string. Those require deliberate
shared scenarios and controlled transports or separately authorized live tests.

## Provenance and reproducibility

The fixtures retain only explicitly printed **Microsoft** observations from
[Windows differential run #202](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/42872964497),
[results artifact](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/42872964497/artifacts/13790049557).
The source commit is `36d9bc3a6d92e0909a55ec44a646e1e56a30443f`.
The manifest pins archive, TRX member, original case-source, current linked-source
and fixture SHA-256 hashes. Each fixture preserves the OS, architecture, SDK,
Microsoft package/build and runtime headers plus original case names/outcomes.

The source archive reports Microsoft Windows 10.0.26100 X64, SDK 10.0.401,
Microsoft packages 9.0.0, and runtimes .NET 8.0.31 / 10.0.12. Expectations are
runtime-specific and never generated from clone results. The importer ignores
clone output, requires exactly one Microsoft line per admitted case, and refuses
missing, duplicate, failed, unknown selected-class cases or inconsistent headers.
It does not parse arbitrary logs, deduce unprinted results or reconstruct values
from assertions. No credentials, directory names or full TRX logs are committed.

After downloading the original `results.zip`, regenerate or verify from the repo
root. Extraction needs the source commit in local Git history:

```sh
python tests/windows/differential-replay/extract.py /path/to/results.zip --check
# To deliberately recreate the committed files, omit --check.
python tests/windows/differential-replay/test_replay.py
```

The runner verifies both recorded files and linked-source hashes. Changing an
exercise requires an explicit provenance review; blindly re-extracting from old
logs cannot establish Windows behavior for changed operations. The manifest's
original-source hashes make that difference visible to review.

## Run offline

Install the .NET 10 SDK and .NET 8/10 runtimes. Restore this bounded project, then:

```sh
dotnet restore tests/windows/differential-replay/AdForLinux.DifferentialTests.csproj
python tests/windows/differential-replay/run.py --framework net8.0
python tests/windows/differential-replay/run.py --framework net10.0
```

`--check-only` verifies inputs and prints the command without executing it.
`--dotnet` selects an installed executable; `--results-directory` selects a parent
for fresh per-run TRX directories. The runner always builds current sources, sets
`ADFL_OFFLINE_TESTS=1` in the child, and verifies exactly 42 passing TRX results
with the recorded case identities. It accepts no filter or additional dotnet
arguments. The loader also requires the production offline guard to be enabled
and validates the embedded fixture hash. These remain application safeguards,
not an OS network sandbox. The existing offline runner allowlists are unchanged.

## Differences policy

Every pilot row explicitly uses `match-microsoft`. There are **no intentional
platform-difference allowances, normalization rules or suppressed failures**.
Unexpected behavior is a failing test, not silently accepted as Linux behavior.
Future intentional differences should be reviewed separately with case identity,
recorded Microsoft result, intended portable result, rationale and tracking link.
They must never overwrite the Microsoft recording or be counted as parity.

## Future Windows recording

`DifferentialRecording.cs` now adds one versioned JSON observation line to every
row in the four replayed classes plus all eight
`PrincipalMissingContextComparisonTests` rows (50 detached rows per framework).
The ordinary differential project compiles the helper automatically. No Windows
workflow, live-test selection or existing offline allowlist was broadened.
Running an already authorized Windows differential selection records these lines
in its normal TRX; recording itself performs no directory operation.

The prefix is `ADFL_DIFFERENTIAL_OBSERVATION_V1: `. Each JSON object contains
`schemaVersion`, exact xUnit `caseId`, `source`, `provenance`, `microsoft`, and
`adForLinux`. Provenance includes OS, architecture, runtime, target, SDK,
commit/build and both Microsoft package/build versions. Existing string
observations retain their format. Missing-context observations use typed fields:
exception/returned type, or setter error/getter error/retained value. Nulls are
preserved rather than converted to empty strings. Only constant detached inputs
and public outcomes are recorded. Do not extend this helper to credentials,
directory contents, arbitrary exception messages or connection settings.

The tests still execute their original Microsoft and portable operations and
assertions once each. The original human-readable output remains. Replay builds
exclude the recording calls and helper, so a Linux replay cannot be mistaken for
a fresh Microsoft observation. Clone fields are diagnostic only;
`structured.py` returns Microsoft observations without the clone field and
checks identity, schema, Windows platform, source commit, runtime target and
package metadata. The legacy importer also rejects conflicting structured values
if a source TRX contains both formats.

Run #202 printed only two of the eight missing-context rows, so that class is
**not** replayed yet. The additional six recorded outcomes do not exist until a
future Windows run actually produces them. Other output-rich classes construct
real contexts or live fixtures and were deliberately not reclassified as offline.
New recordings need a separate source/provenance admission review: `extract.py`
remains pinned to run #202 and its original commit. The structured format does
not make future values trusted or silently replace the retained baseline.

## Validation status

The expanded prototype passes 37 Python extraction/runner/structured-schema tests
and the existing 9 offline-runner tests. Re-extraction of all 84 Microsoft
observations is byte-for-byte identical. Controls cover changed clone output,
changed Microsoft output, missing/duplicate/failed cases, ambiguous observations,
wrong source metadata, changed sources, tampered fixture bytes, exact execution
counts and mismatched structured/legacy values. Python syntax and Git whitespace
checks also pass.

The expanded 42-case project was compiled and executed on Linux on 2026-11-12 using SDK 10.0.404, runtime 8.0.34 and runtime 10.0.15. Both targets passed **42/42 cases with no skips**, and `run.py` verified the exact recorded case names and passing TRX outcomes. All 37 Python extraction/runner/schema checks passed as well. Single-processor MSBuild execution avoided the cloud sandbox's denied worker-pipe creation.

The project remains outside the solution and has its own separate job in the manual `Linux recorded Microsoft oracle (partial)` workflow. Its expectations remain attributed to run #202; they are not new observations from run 43105205156. No live directory operation was performed during this validation.
