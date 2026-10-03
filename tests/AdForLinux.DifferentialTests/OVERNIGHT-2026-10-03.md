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

## Validation

On Linux x64 with SDK 10.0.100:

- Both `net8.0-windows` and `net10.0-windows` build: **0 warnings, 0 errors**.
- Both targets' discovery lists all **20** new cases, without creating the AD fixture.
- Each target's fixture-registration checks: **25 passed, 0 failed**, including both
  new classes. These checks only inspect types; they do not create fixtures.
- An existing ten-case offline collection baseline was attempted through the
  normal Linux runner. All ten stopped at Microsoft's platform-not-supported
  constructor stubs. This is an environment limitation, **not a regression or
  compatibility finding**. Windows behavioral execution remains outstanding.

Build and fixture checks do not establish Microsoft/clone behavioral parity.
Do not run the new live classes as an offline validation command.

## Oracle source leads

- [Microsoft 9.0.0 SearchResultCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs): `ResultsEnumerator.Current`, `MoveNext`, `Reset`, and `InnerList`.
- [Microsoft 9.0.0 PropertyValueCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs): `Value` calls Clear before constructing replacement values; `OnClearComplete` accesses the owner.

The comparisons call the actual package APIs; these sources motivate the probes
and do not substitute for the Windows oracle. No production or workflow files
are changed, no PR/issue is created, and no workflow or comment bridge is invoked.
