# Compatibility coverage: 2026-10-03

## Issue #216 follow-up: 2026-10-04

This follow-up focuses on five areas: staged userAccountControl flags, paging
and ServerTimeLimit, result ownership and lifetime, staged writes and cache
boundaries, and disposed-owner Contains(null) validation. The merged fixes pass
their existing Windows/AD comparisons. Review found two additional gaps in
repeated synchronous Current reads and the first paged request's time budget;
their local corrections and validation are tracked separately below.

The evidence in this table is Windows/AD [run 37218941807](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37218941807)
at `0b76b6d`, using Microsoft **9.0.0**. The complete differential test directory
is unchanged from `bro/compatibility-coverage-2026-10-03` at `61e77bbe`; its Git
tree matches exactly. The implementation includes the merged fixes and both
additional corrections below. Counts are per runtime and are the same on
.NET 8 and .NET 10.

| Target area | Verified contract and current status |
| --- | --- |
| userAccountControl merge | `CompatibilityAccountControlMergeComparisonTests`: **2/2 passed**. Save merges explicitly staged bits with the current native flags, preserving an unrelated native-entry edit. |
| Paging and ServerTimeLimit | `CompatibilitySearchExecutionStateComparisonTests.Fractional_server_limit_preserves_paged_results_like_microsoft`: **1/1 passed**, including PageSize=1 with a 500 ms limit truncated to zero protocol seconds. `CompatibilitySearcherConstructionPagingComparisonTests`: **2/2 passed** for constructor-versus-later filter assignment and retained explicit PageSize. The newly found first-request budget gap is tracked below. |
| Result ownership and lifetime | **23/23 passed**: low-level cursor state/reset (**14/14**), principal wrapper ownership (**2/2**), the original interleaved principal cursor case (**1/1**), binary-buffer replay (**2/2**), queried-principal native lifetime (**2/2**), and Save(context) native ownership (**2/2**). The new synchronous repeated-Current identity correction is tracked below. |
| Staged writes and cache boundaries | The five contracts detailed below passed **15/15**. This includes both persisted write behavior and the values/identities observable through retained wrappers. |
| Disposed Contains(null) | `CompatibilityDisposedPropertyContainsComparisonTests`: **3/3 passed**. Contains validates disposal before null-name validation; the indexer retains null-name-first validation. |

### Staged writes and cache boundaries: five contracts

All cases below passed in the same original-suite AD run on both runtimes. Six of these
15 cases failed in the original issue run. The breakdown makes the separate
cache transitions explicit; no additional production defect was established in
these five paths during this follow-up.

| Contract | Differential comparison | Cases per runtime | Production behavior |
| --- | --- | ---: | --- |
| Whole-value replacement after owner disposal | [CompatibilityRetainedValueReplacementComparisonTests](CompatibilityRetainedValueReplacementComparisonTests.cs), `Whole_value_replacement_preserves_matching_local_state_after_owner_disposal` | 6/6 passed | `PropertyValueCollection.Value` clears the retained local contents before the disposed-owner check throws. Scalar, array and null replacements have live-owner controls. |
| Retained writes across Close | [CompatibilityRetainedPropertyWriteAfterCloseComparisonTests](CompatibilityRetainedPropertyWriteAfterCloseComparisonTests.cs), `Cached_write_through_retained_or_fresh_wrapper_matches_after_close` | 3/3 passed | `DirectoryEntry.OnPropertyChanged` transfers a retained wrapper's write into the rebound cache after Close; fresh and retained wrapper values and identities are compared. |
| Implicit commit cache invalidation | [CompatibilityImplicitWriteCacheComparisonTests](CompatibilityImplicitWriteCacheComparisonTests.cs), `Scalar_write_replaces_managed_cache_at_the_same_commit_boundary` | 2/2 passed | Noncached index assignment persists immediately and clears the managed property cache. Cached assignment retains wrappers until explicit CommitChanges. |
| Rename cache boundary | [CompatibilityRenameRetainedCacheComparisonTests](CompatibilityRenameRetainedCacheComparisonTests.cs), `Rename_retains_or_replaces_managed_cache_like_microsoft` | 2/2 passed | `DirectoryEntry.MoveOrRename` replaces the cache when caching is enabled; noncached mode retains the managed old cn after a successful server rename. |
| Pending writes after credential reset | [CompatibilityCredentialResetPendingWriteComparisonTests](CompatibilityCredentialResetPendingWriteComparisonTests.cs), `Pending_existing_entry_write_after_password_reset_matches_microsoft` | 2/2 passed | Changed then restored Password discards ordinary pending writes on an existing entry through `ResetCredentialBinding`; unchanged credentials preserve them. |

The last contract concerns existing entries and ordinary attributes. Unsaved
children retain creation values, and dirty security descriptors retain their
separate recovery state. Disposed Contains(null) is independently covered by
the three-case comparison in the status table, not included in the 15 cases.

### Additional ownership and paging corrections

Synchronous `SnapshotEnumerator.Current` created a fresh SearchResult on every
read at the same position. The correction caches that result until MoveNext or
Reset. Repeated reads retain identity and local binary mutations; moving or
replaying obtains an independent snapshot.

`StreamingSearchResultTests.Cached_cursor_retains_current_until_it_moves_or_resets`
checks streaming and synchronous modes. The synchronous case failed before the
correction and passed afterward. The differential comparisons from
`bro/compatibility-coverage-2026-10-03` remain unchanged; these additional
regressions belong to the functional suite.

A separate paging gap affects a configured one-second ServerTimeLimit. Starting
the budget when the result source is constructed lets time spent before the
first request consume that budget; integer-second truncation can then suppress
the first request entirely. The follow-up correction starts the budget at the
first dispatch and adds deterministic regressions for that boundary. This is
distinct from the already-passing 500 ms configuration test.

For the requested original oracle, the complete differential test project was
extracted unchanged from `bro/compatibility-coverage-2026-10-03` at
`61e77bbe6cf4d0fd50a0777778e08deb5c54ce77` and built against a separate copy of
the corrected current implementation. Its original disposed-Contains comparison
passed **3/3 on each runtime**, including the named-Contains and null-indexer
controls. This preserves the original assertions rather than substituting the
later test revisions used by the merged CI run.

Final validation of both corrections passed **559/559 Linux functional tests**
on each runtime against an isolated disposable Samba domain, and **42/42 focused
offline regressions** on each Windows runtime. Both new regressions failed
before their fixes. Linux TRX files are saved under
`artifacts/issue216/final-linux/`; the temporary domain and network were removed.
The original Windows/AD issue comparisons also pass, as detailed below. The new
one-second preparation-delay and repeated-Current identity cases are additional
functional regressions; the unchanged original oracle does not assert those
new edge cases directly.

### Original-suite CI evidence

Windows/AD run `37218941807` reported **1,355 passed / 2 failed / 0 skipped** on
each runtime. Its downloaded
[TRX artifact](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37218941807/artifacts/11310071252)
was compared with original run `37189327647` by full test name using ordinal,
case-sensitive matching, including theory arguments.

| Scope | .NET 8 | .NET 10 |
| --- | ---: | ---: |
| Full original differential suite | 1,355 passed / 2 failed / 0 skipped | 1,355 passed / 2 failed / 0 skipped |
| Original issue cases, unchanged assertions and identities | 80 / 80 passed | 80 / 80 passed |
| Original passing controls preserved | 33 / 33 | 33 / 33 |
| Original issue failures corrected | 47 / 47 | 47 / 47 |
| Missing or added test identities | 0 / 0 | 0 / 0 |

The two failures are outside the 80 issue cases and the five focus areas:

- `CompatibilityEntryOptionsLifecycleComparisonTests` for retained **PageSize**
  remains different because the portable DirectoryEntry option default is zero,
  while ADSI supplies its own default. This is the documented #215 compatibility
  decision, separate from DirectorySearcher paging and ServerTimeLimit.
- `GroupScopeValidationComparisonTests.Group_scope_accepts_only_values_defined_by_microsoft`
  contains an old clone-only assertion that undefined GroupScope assignment
  throws. The merged GroupScope fix accepts and retains that value like Microsoft;
  the three original live GroupScope comparisons now pass. This stale assertion
  was deliberately retained in this unchanged original suite.

Of the seven failures outside issue #216 in the original run, six now pass and
the PageSize difference remains. The old GroupScope assertion changed from pass
to fail. No assertion was removed, skipped or weakened for this validation.
Disposable-OU setup, cleanup and TRX upload all succeeded.

[Follow-up machine-readable results](ISSUE-216-FOLLOWUP-RESULTS.json) record every
original issue identity and outcome, the identical test-directory Git trees,
exact baseline changes, and SHA-256 hashes of the original and follow-up TRX
files. [The earlier results](ISSUE-216-RESULTS.json) remain unchanged as evidence
for `eccb8ac`; their eight failures and the then-current retry decision are
historical, not the state validated by the follow-up run.

### Historical retry decision superseded

The merged follow-up also supersedes the earlier decision to permit same-instance
retry after a rolled-back insert. Another Save on that principal now throws
PrincipalOperationException and leaves the DN absent. A new principal with a
corrected password can still be saved. The unchanged differential retry test
passes in the unchanged original-suite AD run; this separate fix is already complete.

## Historical implementation validation at eccb8ac

The historical audit below describes the original test-only branch. Its 80
comparison cases are now included with the fixes on `fix/issue-216-compatibility`.
Validation results for that branch must be read separately from the original
54-failure run linked in issue #216.

Then-current compatibility decision (superseded above): preserve successful same-instance retry after a failed
deferred-password insert has been completely rolled back. AdForLinux restores
the staged principal and permits a corrected password followed by Save. The
pinned Microsoft implementation instead rejects that retry with
PrincipalOperationException and leaves the DN absent. Reproducing its unusable
retry state would remove an existing recovery behavior without protecting any
directory data. The differential comparison remains unchanged and explicitly
reports this intentional difference; rollback and guarded cleanup are still
required. Other contracts in this batch target Microsoft parity.

The seven pre-existing failures (Options #215: two, GroupScope #60: three,
protected Negotiate #56: two) remain outside this issue's fix scope.

Implemented behavior:

- Merge staged account-control bits into the current native flags at Save.
- Truncate configured LDAP time limits to whole seconds and preserve the
  parameterless principal searcher's zero page-size default.
- Validate and rewind low-level cursors; copy binary buffers across replay;
  project independent principals while sharing the principal result position.
- Preserve search-loaded scalar values after native-entry disposal, and retain
  the native entry across Save into another context for the same container.
- Match retained-value replacement failure state, null-Contains disposal
  precedence, writes through wrappers retained across Close, implicit-write
  cache invalidation, noncached rename caches, and credential-reset write loss.
  Dirty managed security descriptors retain their existing failure recovery.
- Preserve extension-cache arrays across Save and local access after Delete;
  allow retained principal-value collections to mutate after owner disposal.
- Preserve bound schema-filter cursor snapshots and VLV response lifetime;
  validate missing search roots before changing the requested projection.
- Respect pending member equality and lifetime; retain small-group Contains
  snapshots without using stale snapshots for membership writes/enumeration.
- Match the protected credential constructor, stored advanced-filter dispatch,
  custom date-finder advancement, and unsaved UnlockAccount behavior.

Linux validation at production commit `eccb8ac`:
[CI run 37193481530](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37193481530)
passed the solution build and **532/532 functional tests on each of .NET 8 and
.NET 10**, with no skips. Six new offline/live functional cases exercise cursor
ownership, replay, time limits, retained collections, and clearing saved members
after an earlier empty membership lookup. Two older clone-only test assumptions
were updated to the verified Windows contracts: local extension-cache access
after Delete and explicit Name assignment for a custom credential constructor.

Windows/AD validation at the same historical production commit:
[run 37193479294](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37193479294)
and [uploaded TRX evidence](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37193479294/artifacts/11299729037).
Both runtimes used the pinned Microsoft **9.0.0** packages.

| Scope | .NET 8 | .NET 10 |
| --- | ---: | ---: |
| Full differential suite | 1,349 passed / 8 failed / 0 skipped | 1,349 passed / 8 failed / 0 skipped |
| Issue #216 cases | 79 passed / 1 intentional difference | 79 passed / 1 intentional difference |
| Original new passing controls preserved | 33 / 33 | 33 / 33 |
| Original new failures corrected | 46 / 47 | 46 / 47 |
| Changed outcomes outside this batch | 0 | 0 |
| Missing original test identities | 0 | 0 |

TRX comparison by full test name against original run `37189327647` confirms
all 1,277 results outside the 80-case batch retained their outcomes (the 1,266
baseline identities plus eleven additional fixture checks). Thus the eight
remaining failures are exactly the seven prior failures listed above and the
documented same-instance retry decision. All 31 report-defined contracts now
have either matching comparisons or that explicit compatibility decision; this
is not a claim of 31 independent implementation defects. The workflow remains
red because the original oracle comparisons have not been weakened or skipped.
Disposable-OU creation, cleanup, and TRX upload succeeded.

[Machine-readable results](ISSUE-216-RESULTS.json) include the exact failure
identities, original-run comparisons, and SHA-256 hashes of both TRX files.

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

## Batch 9: four live-filter and Save(context)-ownership cases

- `CompatibilityLiveSchemaFilterCursorComparisonTests`: capture a bound
  SchemaFilter cursor before indexer assignment or structural replacement.
  Fresh wrappers prove the updated filter; the actual Microsoft captured
  values are compared without assuming COM array identity. The existing
  delegate fixture explicitly omits live ADSI marshaling. No child enumeration
  or persistent write is performed, but binding still requires the lab.
- `CompatibilitySaveContextNativeOwnershipComparisonTests`: retain the native
  entry across Save into the same context instance or a distinct context for
  the same container. Successful saving and independently verified DN/GUID/SAM/
  marker are prerequisites to identity/readability comparisons. **Same-container
  ADSI MoveHere success is unverified**: a rejected Save explicitly reports that
  the lifetime comparison was not reached, not a confirmed ownership gap.
  Created users have guarded exact-DN cleanup; no scalar changes are staged.

Total: **57 cases across 20 contracts**: one observed managed difference and
nineteen live hypotheses. Both new classes build cleanly and discover two cases
per target each. Independent final-file review found no blockers. Neither uses
the shared fixture, so the prior 31 fixture-registration checks remain applicable.
The related retained-SchemaFilter-after-Close COM-lifetime lead was not added:
it risks overlapping existing owner work and requires additional runtime evidence.

Batch 8 was published at `cc81c0cfd835021e8662357c6446e95c99382196`.

## Batch 10: three failed-insert retry and binary-ownership cases

- `CompatibilityFailedInsertRetryComparisonTests`: one same-instance retry
  after rejected deferred password. Independent successful controls for both
  implementations use encrypted SimpleBind; fresh Microsoft reads verify both
  control DNs and non-null LastPasswordSet. Initial rejection and exact-DN
  rollback absence are prerequisites. The same principals receive a corrected
  password and retry Save; actual exceptions/existence are compared without
  prescribing a provider failure code. All four owned users have guarded
  cleanup. This does not duplicate the existing new-instance retry or #56.
- `CompatibilitySearchResultBinaryOwnershipComparisonTests`: two cached
  exact-DN result enumerations, with and without a local mutation to the first
  objectGUID byte buffer. Copied baselines and separate queries before/after
  establish unchanged directory data. Explicit traversal avoids Count/indexer
  materialization. The unchanged control compares contents only; the mutation
  case also compares buffer identity. This is nested-value ownership, distinct
  from existing outer SearchResult identity tests.

Total: **60 cases across 22 contracts**: one observed managed difference and
21 live hypotheses. Both targets build with zero warnings/errors. A cumulative
filtered discovery confirms all 60 cases across 18 classes on each target;
fixture-registration checks pass **32/32** on each. Independent review found no
blocking defects. No AD execution occurred.

The latest bounded audits found no distinct additions in LDAP CopyTo/unsupported
Invoke dispatch, ordinary extension metadata inheritance, certificate thumbprint
multisets, PropertiesLoaded ownership, or already-covered root replacement.
Latest dev and pending owner branch were rechecked unchanged before this batch.
Build/discovery evidence is preserved alongside the original audit at
`/workspace/scratch/compatibility-audit-2026-10-03/validation/`.

Batch 9 was published at `8f2a608efb39e03e4e2524ab80d26972143f09cd`.

## Batch 11: two credential-reset pending-write cases

`CompatibilityCredentialResetPendingWriteComparisonTests` stages Description on
already-persisted owned entries, assigns a temporary password and restores the
original before any binding operation, then commits. Unchanged-password
assignment is the persistence control. Independent Microsoft readers verify
final values and ownership. The temporary value is never used for a bind.
This isolates credential-unbind pending-write survival from unsaved-child
retention, Close, and immediate-write cache invalidation.

Total: **62 cases across 23 contracts**: one observed managed difference and
22 live hypotheses. Both targets build with zero warnings/errors and discover
the two new cases. Final-file review found no blockers; no AD execution occurred.
This class does not use the shared fixture; the prior 32 registration checks
remain applicable. The bounded security-wrapper audit found matching guards,
base delegation, factories, dirty-state tracking, and existing integration
coverage. An ordinary Principal.Name-plus-Save rename assumption was rejected:
pinned Microsoft source writes the name property without calling Rename, so no
success-expecting probe was added for that hypothesis.

Batch 10 was published at `da20ec15c9dd8cf7f7f3dcc485ee25cf8495193f`.

## Batch 12: two account-control flag-composition cases

`CompatibilityAccountControlMergeComparisonTests` stages PasswordNeverExpires
on an owned disabled user, optionally commits NOT_DELEGATED through the same
borrowed native entry, then saves the principal. Fresh Microsoft reads establish
initial, intermediate, and final persisted state. Observations mask only the
three relevant flags; native edits preserve other bits. The unchanged-native
row is a control, and the disabled bit is checked throughout.

Microsoft merges the staged Boolean into current native flags at Save; the clone
stages the complete integer at assignment. This is independent-bit composition,
not the existing #213 scalar-retention-after-refresh mechanism. Ownership uses
a separate marker, SAM and GUID with exact-DN leaf cleanup.

Total: **64 cases across 24 contracts**: one observed managed difference and
23 live hypotheses. Both targets build with zero warnings/errors and discover
the two new cases; independent final-file review found no blockers. No live
execution occurred. This class adds no fixture consumer. A ComputerPrincipal
SAM-suffix hypothesis was rejected because both pinned implementations preserve
the assigned text; no suffix variant was added. Search-request filter/projection
configuration is captured before streaming begins; a remaining asynchronous
time-budget timing lead would require a race and was not turned into a test.

Batch 11 was published at `79502e76baa09180c197890bc0055ad1ceeb6364`.

## Batch 13: sixteen public subclass and unsaved-state cases

| Test class | Cases | Candidate and controls |
| --- | ---: | --- |
| `CompatibilityAdvancedFilterOverrideComparisonTests` | 2 | A virtual getter returns the base filter or a separate populated filter. Microsoft query translation reads its stored filter directly. Baseline, base-getter criterion, and recovery checks isolate dispatch from detached filter storage (#209). |
| `CompatibilityPendingMemberEqualityComparisonTests` | 2 | Two independently loaded wrappers have the same verified DN/GUID. Reference-equality custom principals contrast with ordinary principal equality; pending Contains should honor the equality result. Group edits remain unsaved. |
| `CompatibilityDisposedPendingMemberComparisonTests` | 2 | Pending membership is established before optional member disposal. Microsoft checks its inserted list before consulting member properties; the live-member case is the control. |
| `CompatibilityMemberCursorOwnerLifetimeComparisonTests` | 3 | A positioned unsaved-member cursor observes Current and Reset with a live group, disposed group, or disposed cursor. Collection Count proves group disposal separately. The existing clone-only contrary expectation is untouched. |
| `CompatibilityUnsavedUnlockComparisonTests` | 2 | Repeated UnlockAccount on a normally constructed unsaved user is a Microsoft no-op. Null identity/unlocked state and the disposed-principal guard are controls. No account is saved. |
| `CompatibilityAuthenticableCredentialConstructorComparisonTests` | 3 | A real subclass exposes the protected credential constructor, which skips missing SAM/password and leaves Name unset. Supplied credentials and explicit-assignment control distinguish this overload from public User/Computer constructors. Passwords remain staged. |
| `CompatibilityCustomDateFinderComparisonTests` | 2 | Built-in generic and custom user-type expiration finders compare first MoveNext only. Both public built-in finders must first return the known fixture DN at its seeded expiration. No custom Current cast or unique-result assumption is made. |

Total: **80 cases across 31 candidate contracts**, in **27 classes**: one
observed managed difference and thirty live-test hypotheses. Three cases are
offline; **77 require separately authorized live execution**. These sixteen new
cases are source-supported only. Two new classes use the existing AD-mutating
fixture; the other five use real contexts that may bind. None ran against AD.
Pinned Microsoft 9.0.0 source and an independent review support all seven
mechanisms; source review is not runtime confirmation. The pending cache-boundary
branch and #215 do not cover these paths. `dev` remains at the documented base.

Batch 12 was published at `bb60e5718394b67f3303d6f7e3bde4b0bbfb09b0`.

## Bounded public-surface map and quality checkpoint

Rechecked after batch 13 at `d1e656648f9bbd4303b6459d05a68d01adb530c7`.
This is an inventory of examined families, not a claim of exhaustive API coverage.
Existing coverage means authored tests; it does not imply a current Windows pass.

| Examined public family | Existing or pending coverage | Distinct mechanisms added here / disposition |
| --- | --- | --- |
| Low-level result cursors and result values | Existing CopyTo validation, materialization identity, deferred errors and post-dispose collection access | Current/Reset cursor states and binary-value ownership across repeated cached enumeration. Exact-DN positive queries precede empty/disposed probes. |
| Entry properties, cache and lifetime | Existing credential-wrapper invalidation and failed refresh; pending farm owns fourteen cache/view families listed below | Retained whole-value setter, null Contains after disposal, Close/rebind writes, implicit-write wrapper invalidation, rename cache mode, and pending writes across credential reset. No fake timestamp objects or absent-attribute refresh assumptions. |
| Entry children and schema filters | Existing child cursor tests; pending farm owns Add/Find cache inheritance and SchemaEntry path | Live SchemaFilter index/structural mutation cursor comparison. Credential propagation aligns in source; direct Find/Add filter effects and retained native-filter lifetime deferred because ADSI runtime behavior is not established. |
| Entry options and security | Existing options lifecycle and security-rule suites; #215 owns PageSize/SecurityMasks after Close | No duplicate rows. Security wrappers use matching base APIs, validation and dirty tracking in the examined paths. Provider defaults are not hard-coded. |
| Searcher configuration and execution | Existing validation, timeout, option coupling, projection, malformed-filter and native failure suites | Constructor paging, subsecond execution limit, missing-root projection state and VLV result-disposal state. Managed whitelist audit found zero differences; streaming timing/race variants deferred. |
| Principal query translation and subclass dispatch | Existing advanced dates, culture, detached filters (#209), metadata, generic-finder validation and identity tests | Virtual filter getter dispatch, custom date finder first advancement, and protected credential constructor. Custom date Current casting is deliberately not assumed. Ordinary Name assignment is not treated as a rename. |
| Principal result and native-entry ownership | Existing result disposal and native searcher replacement | Repeated/interleaved Current ownership, cold queried values after native Close/Dispose, and Save(context) native ownership. Same-container MoveHere success remains an explicit runtime prerequisite. |
| Principal persistence and account state | Existing insertion/expiration/workstation/credential suites; protected-Negotiate #56 excluded | Extension cache across Save/Delete, same-object failed-insert retry, account-control bit composition, and unsaved UnlockAccount. Valid password controls, exact absence/readback and masked UAC assertions guard the relevant premises. |
| Group membership | Existing lifecycle, deleted-owner collection and enhanced CopyTo tests; closed #60 GroupScope excluded | Small-group external membership refresh, pending custom equality, disposed pending member, and cursor owner lifetime. Add/Remove equality variants repeat the Contains mechanism; no bulk mutator exists. |
| Membership CopyTo metadata | `Members_collection_contract_matches` and [#203](https://github.com/eliiran1231/active-directory-for-linux/issues/203) already cover this family, including rank and index-at-length parameter differences | Genuine short capacity is not an exact existing row, but adds only another ArgumentException parameter-name variant (Microsoft null versus clone `array`); both buffer before writing. Excluded as the same low-impact family, not reported as an already-tested exact edge or a new practical defect. |
| Principal value collections | Existing interface/null/index, equality dispatch, mutation-attempt invalidation, cursor disposal/reset and typed/non-generic copy suites | Retained SPN collection mutation after owner disposal. Other examined paths have coverage; custom-equality reentrancy and clock-granularity races were not converted into nondeterministic tests. |
| Context and credential validation | Existing constructor/option/disposal precedence and Issue56 authentication tests | No distinct added path. Null/whitespace credentials can reach real authentication; no offline probe assumes otherwise. Context disposal alone does not invalidate the examined cold queried-property path in source. |

Quality boundaries retained across the cumulative tests:

- The three offline cases use a parameterless entry and dispose before owner
  access. The other 77 cases remain live-only, including tests whose bodies
  merely configure objects: real PrincipalContext construction/native searcher
  initialization may bind, and eleven new classes consume the AD-mutating fixture.
- Owned persistence probes preflight exact candidate DNs and use independent
  ownership markers/SAM and GUID checks before leaf cleanup. Rename checks both
  old/new DNs. Unknown partial creations are not deleted; cleanup failures retain
  the primary failure. Existing fixture ownership remains its own responsibility.
- No staged timestamp substitutes for a genuine ADSI LargeInteger. The new
  expiration finder uses the fixture's explicitly persisted UTC date and proves
  the exact fixture DN is returned by both built-in finders before comparing
  custom first advancement. Case-insensitive DN comparisons use ordinal/invariant
  handling; no new test infers locale-sensitive or cross-timezone parity.
- Provider-specific operations retain prerequisites: supported sorted VLV and a
  proven three-row baseline; actual SchemaFilter behavior from the package;
  successful same-container Save(context); password-policy rejection and valid
  password control; specifically verified missing-DN failure. Failure to establish
  one of these is a setup/premise result, not a confirmed compatibility defect.
- Pinned Microsoft **9.0.0** remains the oracle for both framework targets.
  Builds, discovery, fixture reflection and source review are separate evidence
  from behavior. No AD/Windows execution was attempted or requested by this audit.

The [evidence manifest](OVERNIGHT-2026-10-03-EVIDENCE.json) records the exact
27-file inventory, per-class case counts, source SHA-256 values, pinned source
commit, runtime versions and validation-log hashes. Independent cumulative
reviews covered the earlier 57 and later 23 cases with no blocking findings.

Reproducible validation inventory at this checkpoint:

| Evidence | Scope and result |
| --- | --- |
| Differential build | `dotnet build tests/AdForLinux.DifferentialTests --no-restore --nologo`; both targets, zero warnings/errors. |
| Cumulative discovery | `dotnet vstest <target DLL> --ListTests --TestCaseFilter:<OR of the 27 new fully-qualified class filters>`; exactly 80 rows per target, with no fixture construction. The new files are the `*Tests.cs` paths in `git diff --name-only f3c01ab52c4be824819b637fe0bb4702f43138d0 d1e656648f9bbd4303b6459d05a68d01adb530c7`. |
| Safe fixture checks | `dotnet vstest <target DLL> --TestCaseFilter:FullyQualifiedName~FixtureRegistrationTests`; 34 passed per target. |
| Managed oracle evidence | Three new offline cases: one expected comparison failure and two controls passed per runtime. Four existing audited classes: 90 passed per runtime. These used temporary copies with official Windows implementation DLLs; normal Linux facades reject the operations. |
| Deterministic audit | Maintained project and exact per-runtime hashes/results in [Compatibility.ManagedStateAudit](../Compatibility.ManagedStateAudit/README.md); 120,000 operations and 2,400,000 comparisons per runtime, no differences in the whitelist. |
| Retained logs | Workspace `scratch/compatibility-audit-2026-10-03/validation/` contains build, per-batch/cumulative discovery, fixture and managed logs; adjacent TRX files preserve the offline observations. `tests-only.patch` preserves the cumulative patch. These workspace paths are execution evidence, not portable repository paths. |

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
- Both targets' discovery lists all **80** new cases across the thirteen batches,
  without creating the AD fixture.
- Each target's fixture-registration checks: **34 passed, 0 failed**, including
  all eleven new fixture-consuming classes. The paging and SPN classes need configured
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
  were not changed, and the 77 new live cases were not included.
- Independent read-only review of all twenty-seven new classes found no blocking test
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
