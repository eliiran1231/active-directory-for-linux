# Bounded local invariant investigation

This local-only follow-up starts at `9654676a417e3287ad6e0f4037702889e94e024d`.
It adds no Microsoft recordings or production behavior changes. The earlier 220-case
Windows boundary manifest remains prepared but unmeasured; this investigation does
not answer its native acceptance, error-precedence or size-limit questions.

## Reproduction and limits

Build the solution in Release, then run `tests/run-bounded-invariants.py` with
`--dotnet` pointing to the SDK executable, `--framework net8.0` or `net10.0`, and
an empty `--results` directory. Supply the normal local SDK/cache environment.
The Linux-only runner does not restore packages or start Windows/live-directory work.
Each of five methods runs in its own process group. The runner requires one actual
passing TRX result, stops on the first failure, and preserves earlier output.
Tests skip unless `ADFL_BOUNDED_INVARIANT_WORKER=1`; the runner sets it. They are
outside the normal offline CI class filter. Do not enable them in an unrestricted
unfiltered functional-suite invocation: other classes use live directory fixtures.

Limits per worker: 256 MiB managed heap, 8 GiB virtual address space, 30 CPU seconds
per process, 60 wall seconds for the worker group, disabled core dumps, and a
64 MiB evidence-output threshold polled every 200 ms. The output threshold can
overshoot between polls; it is not a hard filesystem quota. An initial global
64 MiB `RLIMIT_FSIZE` caused the .NET 8 test host to exit 153 before any test ran.
Diagnostic output and a controlled rerun isolated that runner restriction; the
final runner limits evidence files instead. Heap/address/CPU/wall limits are retained.
This was a harness startup failure, not a descriptor invariant failure.

## Executed finite matrix

Deterministic random seed: 2261010, with successive group offsets. Recorded closure
seeds: 2369, 2402, 2418, 2540, 3751, 3883, 4164, 4302, loaded from each runtime's
existing committed recordings. These include conditional, resource-attribute and
access-filter forms. Generated outcomes are local properties, not native expectations.

Both Linux runtimes produced the same branch counts:

| Group | Cases per runtime | Results |
| --- | ---: | --- |
| Recorded descriptor byte mutations | 1,024 | 522 accepted exactly; 502 refused |
| Recorded SDDL character mutations | 512 | 77 parsed, 435 refused; 14 of 77 exported losslessly, 63 refused export |
| Conditional payload byte mutations | 1,024 | 153 formatted exactly; 871 refused |
| Detached descriptor edit-back | 256 | 140 accepted; 116 refused atomically |
| Unary expressions, depths 256/2,048/8,192 | 6 | Three complete forms roundtripped; three missing-close forms refused |

Total: 2,816 mutation iterations plus six deep cases per runtime, or 5,644 case
executions across the final .NET 8/10 runs. These are iterations, not a claim that
every generated input is unique. Diagnostic/repeated runs are not added to coverage.
Mutation mode and seed selection are deterministic and correlated; this is not a
Cartesian product, exhaustive grammar test, coverage-guided fuzzer or security proof.

## Invariants and findings

- Raw parse success reproduces the entire supplied buffer, including accepted
  unknown/trailing data; failure never changes input. Returned buffers and original
  input can be overwritten without changing the immutable model.
- Successful text imports survive binary serialization/reparse. Text export either
  reproduces all resulting bytes or refuses without changing the descriptor. String
  mutations include NUL, unpaired surrogates, non-ASCII characters and delimiters.
- Conditional export preserves the input and reparses to the identical payload.
- Edit-back preserves exported snapshot/baseline defensive copies. Failed publication
  preserves state identity, mutation version, pending intent, wrapper/peer flags and
  observable bytes; the same edit session remains usable for a no-op retry. Successful
  edits appear coherently in the shared peer. Inputs include unsupported FL bytes after
  a staged SACL edit, exercising rollback with pre-existing owner intent.
- Deep cases run within the worker limits and below a 64 MiB per-case allocation
  budget. The complete depth-8,192 parse/format/reparse case allocated 6,081,752 bytes
  on both runtimes. Malformed cases refused; no timeout, memory-limit or output-limit
  failure occurred in the final runs.

No internal invariant failure reproduced in this finite matrix. No production fix,
preservation-policy relaxation, native exception guess or new acceptance claim follows
from this negative result. Raw write state remains distinct from observable state.
No resolver credentials, connections or authority were copied or exercised.

## Local verification

Both runtimes passed all five bounded worker tests. Each also passed 11,869 normal
six-class offline core tests, 55 fixture-free consumer tests, 34 metadata-only fixture
registration tests and four Linux-applicable companion tests (14 Windows-only groups
skipped). An initially incorrect registration filter matched zero tests; those empty
runs are not counted. The corrected `FixtureRegistrationTests` filter ran all 34.
The full six-project Release build succeeded with zero errors; the incremental build
reported zero warnings (the preceding functional build reported 14 existing xUnit2013
warnings). The recovery patch is recorded with the local checkpoint evidence.
Full unfiltered functional or
differential suites are deliberately not executed because their fixtures require AD.
No remote publication, workflow, live AD, new Windows measurement or approval was started.

Remaining work includes the unmeasured boundary matrix, broader conditional/resource/FL
combinations and descriptor reconciliation cases, and the existing identity/SDDL/
ObjectSecurity compatibility boundaries in `issue-226-remaining-compatibility.md`.
