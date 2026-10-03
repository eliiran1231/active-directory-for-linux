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

## Batch 4: 15 cases, five further mechanisms

| Class | Cases | Mechanism and controls |
| --- | ---: | --- |
| `CompatibilityDisposedPropertyContainsComparisonTests` | 3 | Disposed owner versus null name validation in Contains. Named Contains and null indexer are controls. All are offline. |
| `CompatibilityRetainedPropertyWriteAfterCloseComparisonTests` | 3 | Write through a retained value wrapper after Close, then read the owner's new wrapper. No-Close retained write and Close/fresh write are controls. |
| `CompatibilityRetainedPrincipalValuesAfterDisposeComparisonTests` | 6 | Retained ServicePrincipalNames Add/RemoveAt/Clear after owner disposal, with live-owner controls. One callback/lifetime mechanism, not three independent bugs. Computers remain unsaved. |
| `CompatibilitySearchExecutionStateComparisonTests` | 3 | Paged subsecond ServerTimeLimit (one case with independent paging/timeout controls); projection retained after a proven-missing root fails (FindOne/FindAll, each with successful recovery). |

After batch 4: **40 cases**, covering **11 contracts**. Ten contracts remain live-test
hypotheses. One managed validation difference was directly observed with the
actual pinned Windows implementation assemblies loaded on Linux:

```text
Disposed Properties.Contains(null):
Microsoft: ObjectDisposedException, ObjectName="DirectoryEntry"
AdForLinux: ArgumentNullException, ParamName="propertyName"
.NET 8.0.22: 1 failed, 2 passed
.NET 10.0.0: 1 failed, 2 passed
```

These are comparison failures from the new test, not a Windows-hosted lab run.
The parameterless entries are disposed before any operation that could bind;
the two successful controls verify the independent disposed/named and
null/indexer validation paths. To reproduce offline on Windows:

```powershell
dotnet test tests/AdForLinux.DifferentialTests --filter FullyQualifiedName~CompatibilityDisposedPropertyContainsComparisonTests
```

The remaining 12 new cases were built/discovered only. Close/write and search
classes use the existing fixture, which creates and deletes objects. The SPN
class uses valid contexts and unsaved principals; context initialization can
bind. None of these live classes was executed in this environment.

The earlier managed searcher audit is now reproducible from checked-in
[harness source and commands](../Compatibility.ManagedStateAudit/README.md),
with [compact results and assembly hashes](../Compatibility.ManagedStateAudit/RESULTS.md).
It remains separate from the solution/workflows. The maintained harness adds
runtime/hash diagnostics and a failing exit status; its new source hash is
recorded in RESULTS.md, separate from the original temporary harness hash.

## Batch 5: three extension-persistence cases

`CompatibilityExtensionPersistenceLifecycleComparisonTests` adds Save/no-Save
retained-array alias cases and one cached-extension-after-Delete case. The
branch total is now **43 cases across 13 contracts**: one directly observed
managed difference and twelve live-test hypotheses.

The Save case distinguishes clearing an extension cache from retaining its
supplied array after successful persistence. A fresh exact-DN read verifies the
stored marker first and again after the purely local array mutation. The
no-Save row is a control. The Delete case stages a cache entry after Save,
deletes the owned user, proves exact-DN absence, and compares cached read/write
behavior while an ordinary Name getter confirms the deleted state.

Both providers use normal UserPrincipal-derived constructors with valid
contexts. Full-GUID CNs, short unique SAM names, absence preflight, and fresh
GUID/marker checks guard exact-DN cleanup. Unrecognized partial creations are
not deleted; cleanup reports that failure alongside the original test error.
These cases create/delete users when run and require the authorized isolated
lab. Here, only both-target build/discovery and independent source review ran.
There were no blocking review findings and no live execution.

Batch 4 was published at `3ccfb6a940ca613669c4517cdf2a7064ec898b70`.

## Batch 6: two small-group membership-cache cases

`CompatibilitySmallGroupMembershipCacheComparisonTests` compares retained
Members.Contains after an external member removal and a full native-entry
refresh, with an unchanged-membership control. Total: **45 cases across 14
contracts**, one observed managed difference and thirteen live hypotheses.

Both uniquely owned groups are seeded through independent raw Microsoft entries,
then reloaded before the first Contains. No completed insertion list can mask
the membership query. Fresh server reads prove the mutation, and fresh principals
must observe that server state. Full RefreshCache avoids coupling this probe to
the pending absent-attribute partial-refresh family. Exact-DN cleanup checks
unique SAM, marker and saved GUID and preserves primary failures.

Pinned Group.IsSmallGroup retains a SearchResult used by ADStoreCtx membership
checks; the clone reads current ranged membership. This is source support only.
Both cases build and discover on both targets; no AD execution occurred.
Independent review found no blockers after the full-refresh refinement.

Batch 5 was published at `16c8484876e6ce4f2898d86be1bdd4395f9fe8c9`.

## Batch 7: four native-lifetime and rename-cache cases

- `CompatibilityQueriedPrincipalNativeLifetimeComparisonTests`: native Close
  and Dispose before the first queried principal Description read. Raw entries
  verify the seeded value without priming that high-level getter. Microsoft
  retains the search-result snapshot; the clone's cold read uses its native
  entry. Close is the successful rebind control. The fixture performs writes;
  the test body only reads and changes local object lifetime.
- `CompatibilityRenameRetainedCacheComparisonTests`: rename with caching
  disabled/enabled after explicit cache priming. Independent reads prove the
  new CN/GUID and old-DN absence. Microsoft can retain its managed dictionary
  in the non-caching path, whereas the clone resets it. Cache mode is assigned
  before retaining wrappers; no ObjectSecurity access changes the premise.
  Owned users have full-GUID CNs and SAM/marker/GUID checks at both exact cleanup
  locations, including partial-failure recovery.

Total: **49 cases across 16 contracts**. One managed difference is observed;
all fifteen live mechanisms remain source-supported hypotheses. Both new
classes received independent review with no blocking findings. Both targets
build cleanly and discover all four new cases. No live execution occurred.
Latest dev remains `f3c01ab`; open #215 and the pending cache branch remain excluded.

Batch 6 was published at `0ccd3deccd1e189c990a7949c083e5422aa357ba`.

## Batch 8: four implicit-write and VLV-lifetime cases

- `CompatibilityImplicitWriteCacheComparisonTests`: known-single description
  index assignment with caching disabled/enabled. Independent reads prove
  immediate persistence or staging. Wrapper identity is captured before an
  explicit commit can mask the transition; the later commit verifies final
  persistence only. Cleanup uses a separate otherTelephone marker plus exact
  DN, SAM and GUID, so editing description cannot erase ownership evidence.
- `CompatibilityVlvResultDisposalComparisonTests`: dispose results after the
  first row or after EOF, then read the searcher's VirtualListView. Separate
  sorted and fully exhausted VLV queries prove the exact three-object set and
  one-row window before touching the candidate cursor. Only the control reaches
  EOF. Clearing the option must recover a null getter after error capture.
  DirSync shares this mechanism and was not added as a duplicate requiring
  extra replication permissions.

Total: **53 cases across 18 contracts**: one observed managed difference and
seventeen source-supported live hypotheses. Independent final-file review found
no blockers. Both targets build with zero warnings/errors, discover the four
cases, and pass all 31 fixture-registration checks. No AD operation was run.

Batch 7 was published at `9dfe456cf9f9a1bae066461c5b900fe7e08d9baa`.

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
- A further PrincipalContext audit found matching Domain constructor validation,
  disposed/null/empty credential precedence, and explicit option handling;
  existing cases already cover those mechanisms. No authentication was run.
- A separate offline audit found no distinct candidate in existing timeout,
  coupled-option, VLV, synchronization, collection traversal/copy, contextless
  principal, or borrowed search-root coverage. No filler variants were added.
- Batch 4 distinguishes execution-time timeout handling from setter validation,
  failed-root projection changes from successful projection, retained scalar
  collections from Group.Members, and Close/rebind writes from disposed writes.
  Pending cache-boundary Contains-after-Clear does not cover null-name/disposal
  precedence. Open issues were rechecked: #215, #201 and #15; no overlapping
  owner issue was found. The later Save/Delete extension-cache cases distinguish
  persistence/deletion from the existing unsaved/disposed extension-cache tests.

## Validation

On Linux x64 with SDK 10.0.100:

- Both `net8.0-windows` and `net10.0-windows` build: **0 warnings, 0 errors**.
- Both targets' discovery lists all **53** new cases across the eight batches,
  without creating the AD fixture.
- Each target's fixture-registration checks: **31 passed, 0 failed**, including
  all eight new fixture-consuming classes. The paging and SPN classes need configured
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
  were not changed, and the 50 new live cases were not included.
- Independent read-only review of all fourteen new classes found no blocking test
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
  The maintained equivalent is now committed under `tests/Compatibility.ManagedStateAudit`.

Build and fixture checks do not establish Microsoft/clone behavioral parity.
Do not run the new live classes as an offline validation command.

## Oracle source leads

- [Microsoft 9.0.0 SearchResultCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs): `ResultsEnumerator.Current`, `MoveNext`, `Reset`, and `InnerList`.
- [Microsoft 9.0.0 PropertyValueCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs): `Value` calls Clear before constructing replacement values; `OnClearComplete` accesses the owner.
- [Microsoft 9.0.0 PropertyCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyCollection.cs): Contains owner access precedes its provider call; the indexer has separate null validation.
- [Microsoft 9.0.0 DirectorySearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs): root binding precedes ADsPath augmentation, and search preferences truncate timeout seconds.
- [Microsoft 9.0.0 principal ValueCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/ValueCollection.cs): retained mutation methods work on tracked values without consulting the principal owner.
- [Microsoft 9.0.0 PrincipalSearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs): constructor calls to `SetDefaultPageSizeForContext` versus the QueryFilter setter.
- [Microsoft 9.0.0 Principal](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs): extension-cache reads/writes and ResetAllChangeStatus across persistence/deletion.
- [Microsoft 9.0.0 FindResultEnumerator](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/FindResultEnumerator.cs) and [ADEntriesSet](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADEntriesSet.cs): each Current read projects CurrentAsPrincipal.

The comparisons call the actual package APIs; these sources motivate the probes
and do not substitute for the Windows oracle. No production or workflow files
are changed, no PR/issue is created, and no workflow or comment bridge is invoked.
