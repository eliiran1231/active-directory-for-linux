# Compatibility coverage: 2026-10-03

Tests-only branch: `bro/compatibility-coverage-2026-10-03`.
Base: `dev` at `f3c01ab52c4be824819b637fe0bb4702f43138d0` (PR #214).
Reference packages remain Microsoft DirectoryServices and AccountManagement **9.0.0**.

## Batch 1: 20 cases, three candidate behavioral differences

| Test class / operation | Cases | Purpose and controls |
| --- | ---: | --- |
| `CompatibilityDirectoryResultCursorComparisonTests.Current_validates_cursor_position` | 8 | Public low-level `SearchResultCollection` cursor before first, positioned, after last, and empty after last, with caching enabled/disabled. The two positioned cases are positive controls. Repeated Current reads compare error and DN. |
| `CompatibilityDirectoryResultCursorComparisonTests.Reset_rewinds_cached_results_after_optional_materialization` | 6 | Reset before first, while positioned, and after last; repeat after Count materialization. Compare Reset rejection and replay. Caching is enabled, so this does not assume replay support for an uncached provider cursor. |
| `CompatibilityRetainedValueReplacementComparisonTests` | 6 | Replace the whole retained `description` value after disposing its owner; compare exception and local contents left behind. Scalar/array candidates, null replacement control, plus all three with a live owner. |

These are **source-supported hypotheses, not runtime-confirmed bugs**. No live
test has been executed in this work environment. Fourteen cursor cases do not
mean fourteen independent bugs: position validation and Reset are two candidate
contracts; the retained setter is a third.

The cursor class uses exact-DN base searches and requests distinguishedName.
A separate successful one-row query for each implementation is a prerequisite,
including for the empty query. It cannot mistake a missing seed or failed bind
for an empty-result incompatibility. Probe collections are closed before the
actual search, and Count is not read unless materialization is the test input.
The value class loads a known populated attribute before disposal and keeps its
original wrappers. Writes are cached only, with no commit or save.
Both classes register the existing fixture, whose setup and cleanup perform AD
operations: execution requires a separately authorized disposable lab.

## Batch 2: four cases, two further candidate differences

- `CompatibilitySearcherConstructionPagingComparisonTests`: two constructor
  paths. Parameterless construction followed by a valid QueryFilter assignment
  may retain Microsoft's zero default page size; the filter-taking constructor
  is the 256-page-size control. An explicit subsequent PageSize assignment must
  survive repeated native access in both cases. Native initialization can bind;
  no query or write is performed.
- `CompatibilityPrincipalCurrentOwnershipComparisonTests`: two reads of Current
  at one known user, with and without disposing the first returned wrapper.
  Compare wrapper reference identity and whether the second remains readable.
  Each returned DN is verified before disposal, and the exact query must have
  one row. Cleanup uses reference identity, not Principal.Equals, and disposes
  each distinct returned principal.

After batch 2, the branch contained **24 cases** covering **five candidate contracts**.
Batch 1 was published at `6842d8ce539616fb0a358ab79b66a85c17cb9b8f`.
These additional cases also require the Windows lab and are not confirmed bugs.

## Batch 3: one shared-position case and bounded offline audit

`CompatibilityPrincipalCurrentOwnershipComparisonTests.Interleaved_cursors_observe_matching_shared_result_position`
adds one case, bringing the total to **25 cases and six candidate contracts**.
Two enumerators share one result collection. A advances twice, B advances once,
then A.Current is read again. Microsoft shares an underlying ResultSet; the
clone's cursors use separate list positions. Assertions compare only DN
relationships within each provider. Independent positive queries establish the
exact two seeded users before probing, and all returned principals are disposed
by reference. This differs from wrapper ownership: it concerns which directory
row Current denotes. No live execution has occurred.

Batch 2 was published at `779f3bde70240496dbc2249d742f8cccbaa8264a`.

## Deduplication checkpoint

- Checked latest dev and recently closed fixes through #214; #215 (Options after
  Close) remains excluded. Existing GroupScope/#60 and protected Negotiate/#56
  work is excluded.
- Pending `farm/tests-1791036711586` at
  `0d7f8c487db6b3a59f3e58a060676685a63394f4` is one commit ahead of dev; its four
  files are not merged. Run `37130691365` completed with failure. All fourteen
  candidate families documented in `CACHE-BOUNDARY-COMPATIBILITY.md` on that
  branch are excluded here. Its failed case count is not independently claimed
  from the run conclusion alone.
- Existing `PrincipalSearchResult*Position*` tests cover AccountManagement
  cursors, not low-level DirectoryServices cursors. Existing low-level lifecycle
  tests cover collection identity/disposal, not Current position or Reset.
- Existing failed-array replacement tests use a live owner. Existing disposed
  entry wrapper tests cover wrapper metadata/access, not local contents after a
  retained whole-Value setter fails. Pending cache-boundary tests also do not
  exercise that transition.
- Existing native-searcher projection tests construct the searcher with a
  filter; they do not cover the constructor-versus-later-assignment default.
  Existing PAPI Current position tests read a positioned principal once; they
  do not compare repeated wrapper identity or independent disposal ownership.
- A separate offline audit found no distinct candidate in existing timeout,
  coupled-option, VLV, synchronization, collection traversal/copy, contextless
  principal, or borrowed search-root coverage. No filler variants were added.

## Validation

On Linux x64 with SDK 10.0.100:

- Both `net8.0-windows` and `net10.0-windows` build: **0 warnings, 0 errors**.
- Both targets' discovery lists all **25** new cases across the three batches,
  without creating the AD fixture.
- Each target's fixture-registration checks: **26 passed, 0 failed**, including
  all three new fixture-consuming classes. The paging class needs configured
  contexts but no fixture. These checks only inspect types; they do not create
  fixtures.
- An existing ten-case offline collection baseline was attempted through the
  normal Linux runner. All ten stopped at Microsoft's platform-not-supported
  constructor stubs. This is an environment limitation, **not a regression or
  compatibility finding**. Windows behavioral execution remains outstanding.
- A separate copied output directory was then configured with the unmodified
  pinned package's Windows implementation DLLs, replacing the Linux stubs only
  in that temporary copy. The four audited, purely managed existing classes
  `PrincipalValueCollectionOfflineComparisonTests`,
  `CompatibilitySearcherStateComparisonTests`,
  `CompatibilitySynchronizationComparisonTests`, and
  `CompatibilityVlvStateComparisonTests` report **90 passed, 0 failed on each
  target** (.NET 8.0.22 and 10.0.0). This checks managed code paths on Linux, not
  Windows platform behavior or ADSI. Repository sources/output configuration
  were not changed, and the 25 new live cases were not included.
- Independent read-only review of all four new classes found no blocking test
  defects, including the later interleaved-cursor case. This is source/design
  review, not runtime verification.
- A deterministic managed-state harness (seed `1032026`) exercised **2,000
  sequences, 120,000 operations, and 2,400,000 exception/state comparisons per
  runtime**, with **zero differences on both .NET 8.0.22 and 10.0.0**. It uses a
  source-audited whitelist of 16 searcher scalar/enum/timeout setters, VLV and
  DirSync assignment, Sort assignment, and Dispose. No entry, SearchRoot,
  Find, Bind, or native-handle operation is permitted. This is bounded evidence,
  not exhaustive coverage or an AD integration pass. The harness source hash is
  `6c6eb7cc80101e4fe7bda003a7dc9c63b16b9466e122a5d204a4a33514372c3a`;
  both runs used byte-identical source. Exact projects, output and assembly
  hashes are retained in the execution workspace at
  `/workspace/scratch/compatibility-audit-2026-10-03/`.

Build and fixture checks do not establish Microsoft/clone behavioral parity.
Do not run the new live classes as an offline validation command.

## Oracle source leads

- [Microsoft 9.0.0 SearchResultCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs): `ResultsEnumerator.Current`, `MoveNext`, `Reset`, and `InnerList`.
- [Microsoft 9.0.0 PropertyValueCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs): `Value` calls Clear before constructing replacement values; `OnClearComplete` accesses the owner.
- [Microsoft 9.0.0 PrincipalSearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs): constructor calls to `SetDefaultPageSizeForContext` versus the QueryFilter setter.
- [Microsoft 9.0.0 FindResultEnumerator](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/FindResultEnumerator.cs) and [ADEntriesSet](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADEntriesSet.cs): each Current read projects CurrentAsPrincipal.

The comparisons call the actual package APIs; these sources motivate the probes
and do not substitute for the Windows oracle. No production or workflow files
are changed, no PR/issue is created, and no workflow or comment bridge is invoked.
