# Compatibility coverage and remediation

## Issue #203 implementation status (2026-10-03)

Implementation starts from `dev` at
`b461d4aa41acda658b210387100555fb705f3cf0`, which includes the corrected
oracle inputs from #202 and the merged #199/#200 fix. The production/test
implementation at `0ca8198a5927f45d8eac0c51408fcbe7700fa3e5` was exercised by
[Windows AD run 37112393660](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37112393660)
and rerun with environment reporting at
`71d1ffa304cb95f50914ff6cb6b085e34cd83397` in
[Windows AD run 37112694125](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37112694125).
Both targets report **1,087 total / 1,083 passed / 4 failed / 0 skipped**.
The per-run OU was created and deleted successfully, and the complete TRX
observations were uploaded as `differential-test-results`.

[Linux CI run 37112396767](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37112396767)
at the same implementation commit passed the solution build and the complete
Samba functional suite: **508/508 on net8.0 and 508/508 on net10.0**, zero skips.
Container teardown succeeded.

For the **367 issue-specific cases**, both targets report **365 passed / 2 failed**.
The corrected baseline
[run 37005328583](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37005328583)
at `6a662ccdb7e330b38b0302244a2820db610bae80` had **176 passed / 191 failed**
in the same cohort. This implementation resolves **189 failing test cases per
target**, not 189 independent bugs. The eight fixture-registration cases whose
parameter text names compatibility classes are excluded from these cohort counts.

All 16 corrected inputs now execute their intended comparisons successfully.
This includes the seven timestamp-staging rows, eight rejected-contextless-filter
rows, and the targeted DisplayName refresh row. All three DisplayName refresh
cases pass. The 20 existing credential-cache/unbound-commit tests also pass;
their implementation belongs to #200, not this change.

### Remaining findings: issue must stay open

Two comparisons remain in `CompatibilityEntryOptionsLifecycleComparisonTests`,
`Retained_options_rebind_after_close_like_microsoft`:

| Setting after setting a value and calling Close | Microsoft in this lab | AdForLinux |
| --- | ---: | ---: |
| PageSize, previously 17 | 99 | 17 |
| SecurityMasks, previously 3 | 7 | 3 |

ADSI reads these settings from its provider handle; AdForLinux retains its local
protocol configuration. LDAP does not expose that ADSI handle's defaults.
This change fixes disposed-option access and validation precedence, but does
**not** claim to implement provider-default discovery/rebind. The observed 99
and 7 are not hard-coded into production. These two original comparison cases
remain enabled and failing. They need a separate portable-provider design or
explicitly accepted compatibility limitation before #203 can be closed.

The other two full-suite failures are the unchanged
`Issue56ConnectionInheritanceTests` cases: both fail during protected Negotiate
binding with "The supplied credential is invalid." The same two failures were
already present on main at `73fc72d8ccf604f29f6a83e2f9453bd68396ae0b` in
[run 37107393704](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37107393704),
before this branch. They are reported separately from compatibility mismatches;
the full Windows suite is not green.

### Root causes and implementation changes

The following groups describe code changes; the case totals describe the full
tested families, including passing controls. They are separate from the count
of originally failing observations.

| Investigation group | Cases in cohort | Implementation |
| --- | ---: | --- |
| Collections and enumeration | 118 | ArrayList-backed materialized CopyTo validation preserves destination atomicity and exception metadata; enumeration gets independent result snapshots; cached collection operations survive disposal; child enumerators validate Current and support Reset. |
| DirectoryEntry lifetime/cache | 27 | Retained options reject disposed entries after local argument validation; disposed RefreshCache/MoveTo precedence follows Microsoft; a failed full refresh preserves the prior property wrapper and pending state. The two Close/default cases above remain unresolved. |
| Validation, membership, serialization | 38 | Constructor validation follows credential/options/type order; contextless filters are rejected without changing searcher state; NoMatchingPrincipalException's serialization constructor rejects unsupported serialization; retained membership delays directory access and preserves null validation; collection copy errors match parameter metadata. |
| Result/native-searcher state | 19 | SearchResult reads mutable ADsPath and captures search-time credentials/options; contexts own native search roots; filter replacement retains the native searcher; mapped projections accumulate including duplicates; a failed FindOne retains the temporary native size limit. |
| Query conversion and identity | 41 | PAPI backslash quoting, per-element advanced extension conversion, runtime date/bool conversion, query-time numeric culture, date sentinel clauses, and explicit SAM qualification follow the oracle. |
| Loaded principal projections | 14 | Loaded DisplayName, BadLogonCount, LastPasswordSet and LastLogon values remain cached; a present zero lastLogonTimestamp does not fall back to lastLogon. |
| Persistence | 12 | RDN escaping preserves boundary spaces and leading hashes; an empty serialized workstation string clears the persisted attribute. |
| Deferred errors | 12 | Malformed FindAll filters fail on cursor advancement with matching parameter metadata in cached, uncached and asynchronous modes; recovery on the same searcher is preserved. |
| Real VLV response | 3 | Response state applies the offset, total, context and final percentage setter, preserving Microsoft's visible integer rounding. |
| Unchanged searcher/VLV/synchronization/expiration controls | 83 | All passing controls retained. |

Filter-string comparisons establish public native-filter parity, not successful
execution or result parity for those rendered filters. Identity, insertion,
workstation and real VLV cases execute the operations described by their tests.
Microsoft's date sentinel spelling is retained in the exposed filter. The PR
#204 review found that this ADSI spelling was rejected by the LDAP request
builder. Requests now normalize the four known bare date-sentinel negations
to parenthesized LDAP assertions without changing the public Filter. New
`AdvancedDateRequestTests` cover all 12 affected API/comparison combinations
and preserve escaped literal values and standard negations. New
`AdvancedDateExecutionComparisonTests` execute all 12 combinations against
both providers with past and future cutoffs (24 cases), compare returned DNs,
and check positive timestamp and unset-date controls in the disposable OU.
These additional tests are outside the original 367-case cohort.

The older `DirectorySearchOptionsComparisonTests` response simulation omitted
Microsoft's final TargetPercentage setter. It now replays the complete public
setter sequence from the pinned 9.0.0 DirectorySearcher source and still compares
against a real Microsoft DirectoryVirtualListView. The unchanged real-response
tests independently establish the transition. Four preexisting functional
assertions encoded the superseded escaping/date behavior and were updated to
the verified contract; additional local tests cover quoting, SAM qualification,
copy failure atomicity, result identity and cached access after disposal.
No skips or disabled comparison assertions were added.

### Reproduction and safety

The Windows workflow uses its `ad-lab` environment and per-run disposable OU.
`DifferentialSettings.UsersContainer` now rejects an explicit container override
outside an isolated `AD_BASE_DN`, before fixtures can write to that location.
Ancestry is checked at real RDN boundaries, so an escaped comma cannot disguise
an out-of-OU container as a matching text suffix.
Owned-object preflights and cleanup remain intact.

Both differential targets reference Microsoft DirectoryServices and
AccountManagement **9.0.0**. Starting at `71d1ffa304cb95f50914ff6cb6b085e34cd83397`,
fixture-registration output records OS, architecture, SDK, runtime, target,
commit, and both Microsoft informational versions in each target's TRX.
The final lab run recorded Windows `10.0.26100` x64, SDK `10.0.401`, and
runtimes `8.0.31` and `10.0.12` for `net8.0-windows` and `net10.0-windows`.
Local verification used Windows `10.0.26200` x64, SDK `10.0.302`, runtimes
`8.0.29` and `10.0.10`, and Microsoft package build
`9.0.0+9d5a6a9aa463d6d10b0b0ba6d5982cc82f363dc3`.

Local checks pass on both targets: **154/154** offline Microsoft comparisons
(123 expanded offline cases, 11 DirectorySearchOptions cases and 20 #200
controls), **100/100** selected functional cases, and **29/29** fixture
registration/isolation checks (22 existing cases plus seven new ancestry cases).
The seven ancestry tests were added after the full-run commit cited above and
passed separately on both targets; they do not alter the 367-case issue cohort
or production assemblies. The workflow retains complete target-specific TRX
files; the local checks are not a substitute for the live run.

## Historical coverage branch baseline (2026-10-01)

Base: `dev` at `8023db6d6e63752420628a1ad94871f4dbe2edf0` (2026-10-01).
Only tests and their documentation are added. Microsoft System.DirectoryServices
9.0.0 is the runtime oracle; new cases do not prescribe guessed exception contracts.

Original pre-correction status: the isolated Windows run [36989564937, job 110782352855](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/36989564937/job/110782352855)
executed commit `789adbce45d6528e2b62243909372c5469706f6a` on both target
frameworks. Each target reported **1087 total, 877 passed, 210 failed, zero skipped**.
Of this branch's **367 selected cases (366 new + one enhanced; 123 offline,
244 live)**, **172 passed and 195 failed per target**. Triage identified **16 setup
or premise failures** and **179 comparison mismatches**. The 15 preexisting
failures are outside this correction's scope (associated with the pending #200
work). Failures are test observations, not a count of distinct implementation bugs.

Batch 17 below corrects the 16 defective inputs/premises without production fixes,
skips, or removed cases. At that checkpoint the corrected inputs had not had a
Windows rerun; the issue #203 implementation status above supersedes that status.
Earlier batch sections retain their historical validation status; their “unrun”
statements describe those checkpoints, not the Windows run above.


## Batch 1: boundaries, state transitions and copy contracts

| Class | Discovered cases | Execution requirement | Coverage |
| --- | ---: | --- | --- |
| `CompatibilitySearcherStateComparisonTests` | 39 | Windows, no AD | Three timeout properties at exact tick/Int32-second limits; cache/VLV, scope/attribute and paging/DirSync rejection, reset and recovery sequences |
| `CompatibilityVlvStateComparisonTests` | 21 | Windows, no AD | Derived percentages, overflow/rounding boundaries, zero and changing totals, failed setters, target and context identity |
| `CompatibilitySynchronizationComparisonTests` | 20 | Windows, no AD | Full-width 64-bit masks through constructors/setter, independent copies, reset options and buffer aliasing |
| `CompatibilitySearchResultCopyComparisonTests` | 78 | Disposable Windows AD lab | Typed and ICollection copies of 0/1/2 rows; index/capacity/type/rank/lower-bound boundaries; destination contents after failure |

Total: **158 new cases**, including **80 offline** and **78 live** cases.
Cases compare state after individual operations, exception types and parameter
names. Copy tests also compare every destination slot and identity within each
source collection; they do not depend on server result ordering. Live source
queries are restricted to GUID-suffixed fixture accounts, and cardinality is
checked before copy observations.

## Batch 2: result and enumerator lifecycle, deferred errors, VLV responses

| Class | Discovered cases | Coverage |
| --- | ---: | --- |
| `CompatibilitySearchResultLifecycleComparisonTests` | 30 | Reference identity before/after materialization, Contains/IndexOf, cached and unmaterialized collection access after disposal |
| `CompatibilityChildEnumeratorComparisonTests` | 10 | Current boundaries, Reset before/within/after traversal, repeated replay in empty and three-child private subtrees |
| `CompatibilityDeferredSearchErrorComparisonTests` | 12 | Malformed filters and valid empty controls across cached/uncached/asynchronous search; failure stage, type, HResult, parameter and recovery on the same searcher |
| `CompatibilityVlvResponseComparisonTests` | 3 | Real sorted VLV searches at positions 1/2/3 of three fixture rows; response state and retained configuration identity |

All **55 batch-2 cases require the disposable Windows AD lab**. Cumulative:
**213 cases (80 offline, 133 live)**. Batch 2 builds both target frameworks with
zero warnings/errors; discovery reports all 213 cases, and fixture registration
passes 19/19 without constructing fixtures. Windows oracle/AD execution remains
unrun. The child enumerator tests create and finally delete a unique private
subtree; the other new tests reuse the fixture's existing rows.

Source-backed hypotheses, not runtime-confirmed findings:

- Microsoft's [SearchResultCollection](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResultCollection.cs)
  separately materializes its inner list and creates public result enumerators;
  the clone reuses row objects. Cached collection access after disposal may also
  differ. Comparisons normalize DNs and never require matching LDAP order.
- Microsoft's [DirectoryEntries](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntries.cs)
  has an explicit resettable child enumerator, whereas the clone returns a C#
  iterator. Actual Microsoft Current and Reset outcomes remain the oracle.
- Invalid filters can fail at ExecuteSearch or during the first row retrieval.
  The tests record the failing stage rather than treating any exception anywhere
  as parity. A corrected empty search must subsequently succeed.
- Microsoft's [DirectorySearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs)
  assigns response Offset, ApproximateTotal and TargetPercentage; the final
  percentage assignment recalculates Offset. The clone applies a different
  update sequence. These cases use real response controls, unlike the existing
  synthetic setter-sequence test, and retain the exact 3/3 control.

## Batch 3: constructor precedence and exception contracts

| Class | New cases | Execution requirement | Coverage |
| --- | ---: | --- | --- |
| `CompatibilityContextValidationComparisonTests` | 16 | Windows, no AD | Full PrincipalContext constructor's competing invalid credentials/type/options/name; exception type and parameter precedence |
| `CompatibilityExceptionSerializationComparisonTests` | 7 | Windows, no AD | Protected NoMatchingPrincipalException deserialization constructor with populated/empty/null info; sibling exception metadata round-trip controls |

The existing `GroupPrincipalComparisonTests.Members_collection_contract_matches`
is also strengthened, without replacing its existing comparisons: CopyTo now
compares ParamName and HResult as well as exception type, and covers combined
null-array/negative-index precedence. It is included in the live category and
still requires the isolated lab. This is **one enhanced existing case**, not a
new case.

Cumulative: **236 new cases (103 offline, 133 live), plus one enhanced live
case**. Category discovery therefore selects **237 cases**. Batch 3 builds both
target frameworks with zero warnings/errors. Runtime oracle validation remains
unrun. The constructors use source-audited invalid inputs that fail before
Microsoft server verification; they never attempt valid context construction.
Serialization probes call the public/protected API directly without binary
formatters or serialized byte input.

Pinned Microsoft 9.0.0 source identifies three specific differences that await
runtime confirmation:

- [Context.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Context.cs)
  checks credential/option errors before ContextType/server verification. The
  clone checks context type and unsupported serverless binding earlier, and
  names the options parameter for invalid Domain bind-mode combinations.
- [exceptions.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/exceptions.cs)
  unconditionally rejects NoMatchingPrincipalException's serialization
  constructor; the clone calls the base deserialization constructor instead.
- [PrincipalCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollection.cs)
  leaves the parameter name absent for array-rank and index-at-length errors;
  the clone supplies array/index parameter names. Existing type-only checks
  could not detect these differences.

## Batch 4: retained options, contextless searchers and workstation conversion

| Class | New cases | Execution requirement | Coverage |
| --- | ---: | --- | --- |
| `CompatibilityEntryOptionsLifecycleComparisonTests` | 16 | Disposable Windows AD lab | Retained configuration getters, valid/invalid setters after disposal; provider options after Close/rebind |
| `CompatibilityContextlessSearcherComparisonTests` | 9 | Windows, no AD | Constructor rejection, captured QueryFilter rejection and state; follow-up operations on the resulting empty/disposed searcher (corrected in batch 17) |
| `CompatibilityWorkstationConversionComparisonTests` | 4 | Disposable Windows AD lab | Clear, single empty, two empty and embedded-comma workstation values; Save errors, raw persisted attribute and fresh principal reload |

Cumulative: **265 new cases (112 offline, 153 live), plus one enhanced existing
live case**. Category discovery selects **266 cases**. Both frameworks build
without warnings/errors; fixture registration passes 20/20. None of this batch's
Windows oracle cases has been executed locally. Dev was rechecked at the same
base SHA; #200 and #201 remain the most recently updated PRs.

The [configuration source](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntryConfiguration.cs)
uses the entry's provider handle for option reads/writes; the clone retains local
fields. Retained-wrapper access after disposal and configuration reset after
Close are therefore useful probes. Its negative PageSize parameter contract is
also distinct from DirectorySearcher.PageSize, which #167 already fixed. These
tests do not call password operations or change quotas.

The [PrincipalSearcher source](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs)
rejects the empty extension principal as persisted before constructor initialization
or QueryFilter assignment can consume its absent context. Batch 17 captures this
rejection and compares the resulting state. These tests construct no PrincipalContext.

The [workstation converter](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs)
converts an empty serialized list to null; the clone checks list count before
joining entries. A single empty entry may therefore differ from an empty list.
Each test seeds separate disabled accounts with Microsoft, attempts both cleanups
independently, and reads both persisted attributes through fresh Microsoft
entries to isolate serialization from decoding. No production behavior was
changed to accommodate these hypotheses.

## Batch 5: query escaping, scalar culture and qualified identities

| Class | New cases | Coverage |
| --- | ---: | --- |
| `CompatibilityQueryEscapingComparisonTests` | 14 | PAPI quoting of wildcard/backslash/ordinary characters, dangling escape, parentheses and RFC-looking text; scalar, workstation, SPN and extension paths; subsequent replacement control |
| `CompatibilityExtensionQueryCultureComparisonTests` | 6 | Decimal/double/numeric-array translation under en-US and fr-FR; refresh after changing ambient culture |
| `CompatibilityIdentityQualificationComparisonTests` | 5 | Explicit SamAccountName qualification, empty/trailing/repeated separators, with independent value-only lookup controls |

Cumulative: **290 new cases (112 offline, 178 live), plus one enhanced existing
live case**; category discovery selects **291 cases**. Both frameworks build
without warnings/errors, and fixture registration passes 21/21. Windows runtime
validation is unrun. All batch-5 cases are classified live: even the 20
translation-only comparisons initialize a PrincipalContext that can bind.
Translation cases do not execute searches or mutate directory data. Identity
cases reuse the fixture's existing user and compare returned DNs and exceptions.

[ADUtils.PAPIQueryToLdapQueryString](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs)
interprets PAPI backslash quoting, unlike the clone's unconditional backslash
escaping. Generated filters are observed through each library's public native
searcher; a second ordinary assignment checks recovery and stale-filter behavior.
These cases do not implement a competing escaping algorithm as their oracle.

[ADStoreCtx_Query.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs)
uses current-culture ToString for numeric extension assertions, whereas the clone
formats IFormattable values invariantly. The same source strips a qualifier at
the first backslash for explicit SAM identities; the clone currently normalizes
qualifiers only in its value-only inference path. These are source-identified
differences awaiting Windows runtime confirmation, not reported test failures.

## Batch 6: result-derived entries and expiration persistence

| Class | New cases | Coverage |
| --- | ---: | --- |
| `CompatibilityResultPathMutationComparisonTests` | 10 | Public ADsPath dictionary replacement/removal/invalid values and repair; GetDirectoryEntry after mutable root path/authentication changes for FindOne and FindAll |
| `CompatibilityExpirationPersistenceComparisonTests` | 3 | UTC/Local/Unspecified expiration Save, raw accountExpires and fresh principal ticks/Kind |

Cumulative: **303 new cases (112 offline, 191 live), plus one enhanced existing
live case**; category discovery selects **304 cases**. Both frameworks build
without warnings/errors; fixture registration passes 22/22. Windows/AD execution
remains unrun. All 13 cases need the isolated lab; after changing a result's local
path or the search root to a synthetic authority, tests only construct entries
and read local properties, never bind those paths.

[SearchResult.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/SearchResult.cs)
reads Path through the public ADsPath property collection and stores the search's
authentication flags. The clone captures Path separately and uses its retained
mutable root to create entries. Tests combine the already-supported public
dictionary mutation contract with Path/GetDirectoryEntry and preserve a
same-value control and repair checks.

Microsoft [ADUtils.DateTimeToADFileTime](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs)
calls ToFileTimeUtc directly; the clone calls ToUniversalTime first. This matters
for Unspecified timestamps on non-UTC hosts. The tests log the host timezone and
offset at the fixed test date. **A UTC-host pass does not validate the nonzero
offset distinction.** No test changes the machine timezone or silently skips.

### Inventory decisions after six batches

| Area surveyed | Decision |
| --- | --- |
| Collection copy bounds/type/rank/lower bounds and partial writes | Existing coverage plus batches 1–3 already exercise these; no duplicate matrix added |
| Collection mutation invalidation, null inputs, self-AddRange and replacement-failure state | Existing differential coverage and source agreement made further cases low value |
| Logon-hours in-place edits, reassignment and repeated Save | Already covered by prior differential regressions; not duplicated |
| Certificate persistence, malformed-certificate filtering and change tracking | Existing functional/QBE coverage; thumbprint multiset tracking and malformed input handling agree in source |
| Security-rule enum/inheritance validation and constructor ordering | Existing coverage and source agreement; no speculative expansion |
| DirectoryServicesCOMException public constructors/serialization | Source contracts agree; no redundant sibling serialization matrix |
| LastLogon fallback for a present zero lastLogonTimestamp | Source lead retained, but controlled AD seeding is unresolved; no invented fixture behavior |
| Custom generic equality dispatch | Requires deliberately inconsistent object/IEquatable semantics; omitted as low-priority synthetic coverage |

Further high-value work should prioritize Windows oracle results for these
source-backed candidates and realistic additional lifecycle transitions. The
missing Windows/disposable-AD runtime is a validation limit, not evidence of a
test failure or a reason to weaken an oracle comparison.

## Batch 7: retained membership and oracle audit

`CompatibilityRetainedMembershipComparisonTests` adds **5 live cases** for a
membership collection retained before its owner group is deleted: Count,
enumerator creation, and null Add/Remove/CopyTo argument precedence. Each case
uses two independently Microsoft-seeded, empty groups, primes the collection,
and compares Microsoft outcomes with the clone after deletion. Cleanup targets
only each invocation's exact unique group DNs.

Microsoft [PrincipalCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalCollection.cs)
checks the collection's own disposed state; Principal.Delete marks the owner
deleted without disposing its membership collection. The clone checks owner
deleted state on collection operations. These are source-backed hypotheses,
not runtime-confirmed failures.

The audit also strengthens the existing ten child-enumerator cases: each
Microsoft traversal must complete without error and return the expected row
count, including both reset replays. Enumerator acquisition is inside cleanup
protection; an uncertain subtree commit is checked at its exact owned DN, and
cleanup errors preserve the primary failure.

Cumulative: **308 new cases (112 offline, 196 live), plus one enhanced existing
live case**; discovery selects **309 cases (112 offline, 197 live)**. No Windows oracle or AD operation
has run here.

## Batch 8: insertion names, advanced date queries and cleanup audit

| Class | New cases | Coverage |
| --- | ---: | --- |
| `CompatibilityInsertionRdnComparisonTests` | 8 | Save with leading/trailing/both spaces, leading #, punctuation, slash and plain control; immediate Name/DN and Microsoft-read persisted cn/name/DN |
| `CompatibilityAdvancedDateQueryComparisonTests` | 9 | Inclusive ranges for bad-password/password-set/last-logon/expiration criteria, last-logon inequality presence, and replacement with Equals on the same searcher |

All 17 cases require the isolated lab. Insertion creates a unique private CN
container beneath the configured UsersContainer and deletes that exact owned
subtree, including partial saves. Microsoft insertion and one-row readback must
succeed; only independently generated account tokens are normalized. Query
cases only inspect public native-searcher Filter strings: they do not execute
searches or write objects, but initialization can bind.

Microsoft [ADUtils.EscapeDNComponent](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs)
escapes boundary spaces and leading #; the clone's insertion RDN helper omits
those boundaries. Microsoft [ADStoreCtx_Query.DateTimeFilterBuilder](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs)
adds default-value exclusions for selected date ranges; clone advanced queries
currently omit those exclusions. The tests compare the literal Microsoft Filter
surface without assuming the emitted LDAP syntax is valid or semantically
canonical. Expiration ranges and last-logon NotEquals are controls. Each query
case also checks replacement, with UTC timestamps to avoid host-timezone effects.

The audit repairs workstation/expiration cleanup diagnostics: all cleanup steps
are attempted and their errors retain the original test failure. No case count
changed for these repairs.

Cumulative: **325 new cases (112 offline, 213 live)** plus **one enhanced existing
live case**. Full category selection is **326 cases (112 offline, 214 live)**.
Both frameworks build without warnings/errors; fixture registration passes
22/22. Windows oracle and AD execution remain unrun; all source leads remain
unconfirmed at runtime.

## Batch 9: custom advanced-filter value conversion

`CompatibilityAdvancedExtensionQueryComparisonTests` adds **7 live, translation-only
cases**: true/false booleans, UTC DateTime declared as DateTime/object, string
object arrays, integer object-array ranges, and a scalar string control. Each
case replaces the same criterion and checks successful, changed Microsoft output
before comparing both native-searcher Filter strings. No rendered filter executes;
even replacement values are tested as translation inputs, not schema-valid queries.

Microsoft [Principal.AdvancedFilterSet](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs)
stores these inputs as object arrays. Its extension converter uses each element's
runtime type for boolean/FILETIME formatting and per-element clauses. The clone's
custom advanced-filter path converts the entire supplied value to text and uses
the supplied type metadata for DateTime conversion. Ordinary ExtensionSet numeric
culture conversion was already covered in batch 5; these cases exercise the
separate protected AdvancedFilterSet path. UTC dates remove the timezone dependency.

Cumulative: **332 new cases (112 offline, 220 live)** plus **one enhanced existing
live case**. Full selection is **333 cases (112 offline, 221 live)**. Both frameworks
build without warnings/errors and fixture registration passes 22/22. Windows/AD
execution remains unrun. The branch still contains only tests and documentation.

## Batch 10: disposed-entry validation and cumulative audit

`CompatibilityDisposedEntryValidationComparisonTests` adds **9 Windows offline
cases** for RefreshCache null/null-element/empty/valid arrays and MoveTo/CopyTo
argument precedence after disposal. Both source and destination entries are
disposed before any provider-sensitive operation. Microsoft Bind checks disposal
before ADSI or default-domain discovery; null-parent paths fail before binding.
Tests compare repeated exceptions, parameter names, HRESULTs, disposed object
names and preserved paths. Valid arrays/names and null CopyTo supply controls.

Microsoft [DirectoryEntry.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs)
binds before reading RefreshCache arguments and dereferences the MoveTo parent
before checking the source. The clone validates several arguments first. These
are source-supported precedence differences, not runtime-confirmed failures.

The cumulative audit found no un-restored culture/environment/timezone changes
or new parallel execution. Culture is restored in finally; assembly-level test
parallelism is already disabled. Write tests use distinct generated identities
under the configured UsersContainer. Workstation/expiration cleanup now probes
the exact owned DN rather than depending on a successful SAM lookup, covering
partial creates. Workstation cases establish successful normal Save controls;
clear and one-empty also require successful Microsoft mutation because the
reference converter maps both to null. Other inputs retain real error parity.

Cumulative: **341 new cases (121 offline, 220 live)** plus **one enhanced existing
live case**, selecting **342 cases (121 offline, 221 live)**. Both frameworks build
without warnings/errors; fixture registration passes 22/22. Oracle execution is
still unrun.

### Remaining-area inventory and selection rules

Candidates require a reachable public behavior, a distinct source difference or
meaningful untested transition, and an actual Microsoft observation with a
positive prerequisite/control. Existing regression coverage is checked before
adding cases. Shared environmental failures, fabricated private state and large
redundant argument matrices are not counted as useful parity evidence.

| Public area examined | Current decision / untested limit |
| --- | --- |
| SortOption defaults, null/invalid setters, constructor order | Source agrees; existing DirectorySearchOptionsComparisonTests cover validation. No added rows. |
| VLVContext public constructor and Copy | Source agrees on independent wrappers. Internal context bytes have no public accessor; no private-field probe added. |
| DirectorySynchronization options/cookies/copy/reset | Batch 1 and existing cookie-identity tests cover observable differences. No serialization contract to invent. |
| ActiveDirectorySecurity and access/audit rule constructors/factories | Same BCL delegates and guards; existing security-rule validation tests. A suspected propagation exception difference is unreachable because the base validates first. Actual ACL persistence still requires Windows/AD. |
| DirectoryEntry cache/credentials/path wrappers | Existing regressions and open PR200 checked; no duplicate fixes/tests. Batch 10 adds only uncovered disposed argument precedence. |
| Native ADSI invocation, mutual-authentication status and quota operations | Clone declares provider/platform limitations. No artificial no-server failures added merely to repeat those limitations. Runtime/provider behavior remains untested. |
| Query translation and result lifecycles | Batches 1–9 cover selected state, conversion and lifetime gaps. Actual server execution, paging/referrals/DirSync response behavior and large-directory limits remain unvalidated. |
| Account/group persistence and membership | Selected serialization, identity and delete-lifecycle probes added. Cross-domain membership, trusts, password policy and authorization behavior need a deliberately configured disposable lab; not guessed or executed here. |
| LastLogon zero-timestamp fallback | Controlled server seeding remains unresolved; source lead retained without a speculative test. |

This inventory is a coverage map, not a claim that every public method or
provider combination is exhaustively tested. The highest-value next validation
is the Windows offline subset, followed by selected live cases in the verified
disposable lab; neither environment is available in this execution workspace.

## Batch 11: cached logon projection and final audit pass

`CompatibilityCachedLogonProjectionComparisonTests` adds **3 live cases** for
absent, zero and positive lastLogonTimestamp values in the public property cache.
It saves independent disabled users, obtains their public underlying entries,
checks UsePropertyCache and staged raw values, then compares each principal's
first LastLogon read. Cached FILETIME checks normalize ADSI public large-integer
HighPart/LowPart values as well as Int64. Positive controls must yield a Microsoft timestamp. No
Save, CommitChanges or RefreshCache occurs after staging; cleanup uses fresh
principals and exact owned DNs. This tests cached-value projection only, not AD
acceptance or persistence of timestamp writes.

The pinned Microsoft [ADStoreCtx.Load](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs)
reads the underlying entry's properties for newly saved principals without a
search-result snapshot. [AccountInfo](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs)
leaves LastLogon unloaded after insertion. Microsoft's conversion chooses the
replicated value by attribute presence; the clone falls back after a null
converted value. A zero replicated value is therefore a source-backed candidate;
Windows runtime confirmation is still required.

The cumulative audit corrected disposal in child enumeration and deferred-search
observation: all enumerators/results/tracked entries receive a disposal attempt,
and cleanup errors preserve the primary operation error. Cleanup cannot become
a matching deferred-search stage. No case counts changed for these corrections.

### Evidenced boundary after the remaining-gap pass

- `UserPrincipalComparisonTests` already covers credential validation with valid
  and invalid credentials, explicit TLS/simple and negotiate/signing/sealing
  options, edge option values; `PrincipalBehaviorComparisonTests` covers disposal.
  Further transport fallback cases require controlled transport faults, not a
  generic credential failure or extra bad-password attempts.
- `Issue45GroupQueryComparisonTests` already has a two-domain foreign-principal
  and nested-membership case gated by a second-host/base-DN trust configuration.
  The ordinary fixture configures one directory. No second-domain setup or trust
  evidence was available, and no duplicate cross-domain scenario was added.
- ExtendedDN encodings, attribute-scope queries, property-names-only results,
  custom principal construction and extension attributes have existing tests.
  Child collection Add/Find/Remove disposal paths agree with source; no redundant
  matrix was added. WinNT, Machine and AD LDS provider scopes cannot be inferred
  from an LDAP domain fixture or treated as supported clone behavior.
- Persisted zero-timestamp seeding remains unverified. The existing fixture
  records a real logon; it does not guarantee a present-zero replicated timestamp
  alongside a positive local value. Batch 11 tests only the narrower public-cache
  route, without pretending that schema metadata proves server write acceptance.
- The audit found no additional hidden mutable global state, un-restored culture,
  new ordering dependency, or equal-environment-error pass in the new suite.
  These are source-review findings, not execution proof. Microsoft 9.0.0 is pinned;
  net8.0-windows and net10.0-windows still need separate oracle runs.

This pass established limits for the specific provider, transport and persisted-
timestamp scenarios above. It did not cover sequential getter-cache lifetime:
batch 12 adds read/mutate/reread cases identified by independent review. These
fixture limitations must not be generalized into exhaustion of public-state
transitions; further candidates still need source and existing-coverage checks.

Cumulative: **344 new cases (121 offline, 223 live)** plus **one enhanced existing
live case**, selecting **345 cases (121 offline, 224 live)**. Both target frameworks
build without warnings/errors; safe fixture registration passes 22/22. No Windows
oracle or AD operation has run here.

## Batch 12: sequential scalar getter-cache lifetime

The existing cached-logon class gains **2 cases**: first project a positive
replicated timestamp, replace its public cache value with a different positive
timestamp (or leave the value unchanged as a control), verify the raw cache value,
and compare repeated LastLogon ticks/Kind. No Save, CommitChanges or RefreshCache
runs after staging. These extend batch 11's first-read coverage rather than
repeating its absent/zero/positive matrix.

`CompatibilityCachedScalarLifecycleComparisonTests` adds **6 cases**, changed
and unchanged controls for DisplayName, BadLogonCount and LastPasswordSet. These
represent string, integer and nullable date caches in Principal, AccountInfo and
PasswordInfo. They share the same isolated saved-disabled-user setup; no shared
mutable fixture or extra server precondition was introduced.

Microsoft [Principal.HandleGet](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs#L1025-L1040)
retains a loaded value. Its [AccountInfo.LastLogon](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs#L33-L42)
and the related scalar getters use that load state. The clone rereads the
underlying entry cache on these getters. Tests take Microsoft observations as
the oracle rather than hardcoding that either implementation must retain the
old value. First observations and raw cache prerequisites are checked, and
unchanged controls distinguish cache lifetime from initial-conversion failures.
All eight cases require Windows and account creation in the disposable lab;
they do not assert persistence of any staged attribute value.

Cumulative: **352 new cases (121 offline, 231 live)** plus **one enhanced existing
live case**, selecting **353 cases (121 offline, 232 live)**. Both frameworks build
without warnings/errors; safe fixture registration passes 22/22. Windows oracle
execution remains unrun and the cache-lifetime differences remain hypotheses.

## Batch 13: refresh atomicity, invalidation and native-searcher ownership

| Class | New cases | Requirement | Distinct transition |
| --- | ---: | --- | --- |
| `CompatibilityFailedRefreshWrapperComparisonTests` | 2 | Windows offline | Failed full/partial refresh after disposal; exception plus property-wrapper identity across repeated failures |
| `CompatibilityPrincipalRefreshCacheComparisonTests` | 3 | Disposable lab | Loaded DisplayName after full/targeted/unrelated underlying-entry refresh; independent raw baseline and staged-value controls |
| `CompatibilityNativeSearcherReplacementComparisonTests` | 2 | Disposable lab, translation only | Replace QueryFilter after native searcher creation, same/distinct context instances targeting identical endpoint/container |

Microsoft [DirectoryEntry.RefreshCache](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs)
checks binding and performs the refresh before discarding its property wrapper;
the clone's full refresh clears that wrapper first. Disposed entries establish
this failure-state comparison without ADSI/DNS work. Partial refresh supplies a
control; no attribute values are read in these offline cases.

The live refresh cases distinguish the underlying property cache from the
already loaded Principal field. Each captures its own raw baseline before the
high-level read, stages a unique positive value, verifies initial projection,
and confirms full/targeted refresh restores the baseline while unrelated refresh
retains the staged value. Only then do they compare the principal reread. Refresh
is intentionally read-only here; no Save/Commit follows staging. They reuse the
existing saved-disabled-user helper and exact-DN cleanup.

Microsoft [PrincipalSearcher.QueryFilter](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs)
changes its context without clearing the native searcher; [PushFilterToNativeSearcher](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs)
creates one only when absent. The clone resets it when the context reference
changes. Cases verify updated filter/context, retained native identity and custom
PageSize/SizeLimit, with a same-context control. No Find or Save executes. This
is ownership/configuration behavior, not cross-domain routing.

Reviewed nearby failed-setter candidates without duplicating existing cases:
searcher/VLV/DirSync invalid-set state, collection validation, and sort/security
validation already have coverage or source agreement. Path setter differences
for non-LDAP providers repeat declared scope limitations and were not added.

Cumulative: **359 new cases (123 offline, 236 live)** plus **one enhanced existing
live case**, selecting **360 cases (123 offline, 237 live)**. Both frameworks build
without warnings/errors; safe fixture registration passes 22/22. All compatibility
differences remain source-backed hypotheses; Windows oracle/AD execution is unrun.

## Batch 14: retained native search-root ownership

`CompatibilityRetainedSearchRootComparisonTests` adds **3 live read-only cases**:
keep both owners alive, dispose only PrincipalSearcher, or dispose only
PrincipalContext. Each retains the already-created native search root and
successfully reads its Name before changing lifetime. It then compares Name and
exception observations through that retained entry, not through a disposed PAPI
wrapper. No Find, Save, Commit or independent borrowed-root disposal is used.

Microsoft [ADStoreCtx_Query](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs)
passes its context-owned entry to the native DirectorySearcher. The native
[DirectorySearcher.Dispose](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectorySearcher.cs)
disposes only an internally allocated root, while [PrincipalContext](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Context.cs)
and [ADStoreCtx](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs)
dispose their owned context entry. The clone instead creates a separate root
owned by PrincipalSearcher. The two disposal rows exercise opposite ownership
boundaries; the no-disposal row is a positive control.

The additional sequential-state review found matching PrincipalValueCollection
validation/change-tracking order already covered by existing edge/traversal
suites. ObjectSecurity assignment, null rejection and disposal/reassignment also
agree in source. Its failed-full-refresh descriptor loss shares the pre-validation
cache reset exposed in batch 13, so no duplicate descriptor matrix was added.

Cumulative: **362 new cases (123 offline, 239 live)** plus **one enhanced existing
live case**, selecting **363 cases (123 offline, 240 live)**. Both frameworks build
without warnings/errors; safe fixture registration passes 22/22. Windows oracle
execution remains unrun. Runtime confirmation is required before reporting any
of these ownership differences as observed compatibility failures.

## Batch 15: native projection and failed-search state

Four new live cases cover two source-backed native-searcher contracts:

- `CompatibilityNativeProjectionComparisonTests` (2): repeated access appends
  mapped projection attributes, retaining caller attributes and duplicate counts;
  same-context User-to-User and User-to-Group replacements exercise type changes.
  Sorted JSON arrays preserve multiplicity without assuming mapping order.
- `CompatibilityNativeFailureStateComparisonTests` (2): FindOne and FindAll
  failures expose the retained native SizeLimit. A valid root is read first,
  then Microsoft must prove a unique child DN absent with error `0x80072030`.
  The borrowed root is temporarily replaced, restored in finally, and state is
  inspected before another preparation accessor. These cases perform reads only.

Microsoft source appends its mapped projection on each accessor and restores
FindOne's temporary limit only after a successful native search. The clone does
not populate that projection and restores the limit in finally. These are
**source-backed hypotheses**, not observed Windows failures. FindAll is the
non-temporary-limit control. Initialization/reads still require the isolated lab.

The audit also strengthens existing rows: identity qualification first requires
successful bare-SAM lookups on both APIs; culture conversion requires attribute
presence and culture-sensitive/unchanged controls; synthetic DirSync cookies use
hex diagnostics so equal-length content mismatches are readable.

Cumulative: **366 new cases (123 offline, 243 live)** plus **one enhanced existing
live case**, selecting **367 cases (123 offline, 244 live)**. Windows oracle and AD
execution remain unrun.

## Batch 16: cumulative audit and cleanup ownership

No new cases. A cumulative read-only audit verified independent provider objects,
positive prerequisites for live failure probes, and all eight offline classes'
pre-binding/local-only call paths. Source links remain pinned to `v9.0.0`, matching
the two Microsoft package references in the differential project.

The audit identified a test-only cleanup flaw: marking a generated DN as owned
before a failed creation could delete an object already present at that DN.
All six new writing classes now require authenticated Microsoft RefreshCache to
prove the exact DN absent (`0x80072030`) before enabling cleanup. Generated object
or private-container CNs use full GUIDs; account SAM names remain short. Cleanup
visits only creations actually attempted after that preflight, including partial
creation failures, and still preserves primary and cleanup errors. Reloads use
exact DNs rather than truncated SAM names. The shared helper has no test or fixture.

This prevents the preexisting-DN collision path; it is not an atomic reservation
against a concurrent external writer. The verified disposable isolated lab remains
mandatory. Existing `TestDataFixture` tracks objects after successful creation and
uses best-effort cleanup; its unrelated behavior was not rewritten. Cleanup and
all live prerequisites remain unrun here.

The candidate-family table and explicit per-framework offline commands below form
the handoff. Counts remain **366 new cases plus one enhanced case**: **123 offline,
244 live selections**. None of the compatibility hypotheses is runtime-confirmed.

## Batch 17: correct 16 setup/premise failures from the Windows run

The run linked at the top supplied actual evidence for these corrections. No
implementation code, skip, case removal, workflow dispatch, or AD rerun is included.
All **367 selected cases** remain (366 new + one enhanced; 123 offline / 244 live).

| Defective cases | Correction | Preserved evidence / rerun requirement |
| --- | --- | --- |
| Five `CachedLogonProjection` and two LastPasswordSet rows in `CachedScalarLifecycle` | Microsoft timestamp staging now activates a fresh real ADSI LargeInteger COM object, sets signed HighPart/LowPart, and assigns it through public Properties.Value; clone staging remains Int64 | Full-bit roundtrip checked before and after Microsoft cache assignment; presence/zero and first-projection controls remain. Windows must validate COM activation and cache acceptance. No timestamp Save/Commit occurs. |
| Eight `ContextlessSearcher` operation rows | Capture rejected QueryFilter assignment, compare retained state, then execute the selected operation on each provider's independently reached state, optionally disposed | Microsoft must reject assignment and remain empty; subsequent empty/disposed behavior is compared. These no longer claim an assigned contextless filter reached FindOne/FindAll/native operations. Constructor row remains unchanged. |
| One targeted DisplayName `PrincipalRefreshCache` row | Persist a nonempty raw baseline without loading Principal.DisplayName; verify both server objects through fresh Microsoft wrappers before staging | The three refresh rows share this corrected baseline. Microsoft raw-cache transition is guarded and compared with the clone, then principal projections are compared. Staged marker is never committed; exact-DN cleanup remains unchanged. |

The timestamp representation follows Microsoft's own pinned
[AcctExpirToLdapConverter](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs#L1288-L1318)
and [ADsLargeInteger COM declaration](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/interopt.cs#L73-L83).
It does not access private Microsoft members or fabricate the expected projection.
The CLSID activates the registered Windows ADSI coclass; HighPart/LowPart are public
COM properties. Missing registration or failed staging remains a visible setup
failure, with no fallback or skip.

The [PrincipalSearcher setter](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/PrincipalSearcher.cs)
rejects a Principal whose `unpersisted` flag is false before storing QueryFilter;
the empty protected Principal constructor leaves that flag false. The old eight
rows therefore failed before their intended observation. The corrected rows
preserve the rejection as an actual comparison rather than assuming acceptance.

For targeted refresh, the Windows oracle retained the staged string when the
server omitted the absent displayName attribute. The corrected nonempty baseline
lets GetInfoEx reload an actual server value; full and unrelated-attribute refresh
remain controls. These changes do not suppress the observed high-level cache
retention mismatch or alter the other 179 comparison failures to make them pass.

**Corrected Windows results are pending.** Local builds, discovery, fixture-only
and clone-only checks cannot establish ADSI behavior. Re-run the affected classes
on both Windows targets only in the verified isolated lab; the contextless class
can independently run with the offline category without AD.

## Findings and prior-work check

The Windows run above distinguishes comparison mismatches from setup failures;
corrections still require rerun before claiming those inputs work. Particularly
useful probes are VLV arithmetic beyond small integer totals,
DirSync high-bit validation, and SearchResultCollection's manual copy loops
(validation timing and partial writes). Passing controls are deliberately retained.

Reviewed recent PRs through #201 via the GitHub connector. #167 already fixes
negative PageSize and result-property lookup; existing tests cover these, so this
batch does not report them as new gaps. #200 remains open at
`a7b6ea56879756e7ba3c76d4d9052e6363f4edf2` and contains credential-wrapper/unbound
commit changes plus staged-attribute coverage for unsaved children. Those cases
are excluded here. Prior collection, schema, extension-cache and disposal fixes
in #172–#198 were checked against current test files before selecting this batch.
No workflow was dispatched, listener activated, issue opened, or production fix
made. No AD operation was executed locally.

## Candidate-family handoff

The table records the original source rationale and required validation, not a
per-family runtime verdict. See the Windows totals and setup correction above.
“Source-backed” means the pinned
Microsoft 9.0.0 implementation and clone take different observable paths;
“contract probe” means the edge/sequence deserves oracle comparison without a
claimed source-proven failure. Class names omit the common `Compatibility` prefix
and `ComparisonTests` suffix. The batch sections above give case counts and
pinned source links. Controls belong to the same tests and are not separate gaps.

| Candidate family / test classes | Reason to run | Evidence strength | Validation needed |
| --- | --- | --- | --- |
| Searcher boundaries / `SearcherState`, `VlvState`, `Synchronization` | Tick rounding, derived VLV arithmetic, full-width flags and failed-setter state | Source-backed candidates plus passing boundary controls | Windows offline on both target frameworks |
| Constructor and exception contracts / `ContextValidation`, `ContextlessSearcher`, `ExceptionSerialization`, `DisposedEntryValidation` | Competing validation precedence, serialization and disposed-entry guard order | Source-backed candidates; invalid inputs deliberately fail before binding | Windows offline on both frameworks |
| Failed refresh / `FailedRefreshWrapper` | Whether a failed refresh discards retained property wrappers | Source-backed pre-validation cache reset difference | Windows offline; check repeated failures and wrapper identity |
| Result copying / `SearchResultCopy`, enhanced `GroupPrincipalComparisonTests` | Index/rank/type validation timing, partial writes and parameter metadata | Contract probes with source-backed manual-copy concerns | Isolated Windows lab; cardinality controls must pass |
| Result lifetime / `SearchResultLifecycle`, `ResultPathMutation` | Materialization identity, disposal, mutable ADsPath and search-time root state | Source-backed candidates | Isolated lab; verify source entries before local result mutation |
| Child traversal and retained configuration / `ChildEnumerator`, `EntryOptionsLifecycle` | Reset/Current boundaries and provider-handle state after Close/Dispose | Source-backed candidates | Isolated lab; enumerate owned subtree and verify initial binding |
| Deferred failures and VLV response / `DeferredSearchError`, `VlvResponse` | Failure stage/recovery and composition of real response fields | Contract probes plus source-backed response-update ordering | Isolated lab with supported VLV; corrected search and exact-cardinality controls |
| Query translation / `QueryEscaping`, `ExtensionQueryCulture`, `AdvancedDateQuery`, `AdvancedExtensionQuery` | Quoting, culture timing, date sentinels and typed extension conversion | Source-backed translation candidates | Isolated lab for context initialization; these tests do not execute queries |
| Qualified identity / `IdentityQualification` | Domain/separator handling while locating the same fixture user | Source-backed candidate with malformed-form probes | Isolated lab; per-row bare-SAM lookup prerequisite |
| Persistence / `WorkstationConversion`, `ExpirationPersistence`, `InsertionRdn` | Serialization to attributes, date kind and escaped insertion names | Source-backed candidates | Isolated lab; inspect persisted values; Unspecified expiration also needs a non-UTC Windows host |
| Retained deleted membership / `RetainedMembership` | Collection behavior after its owning group is deleted | Source-backed owner-guard candidate | Isolated lab; unique empty groups, successful initial count and delete |
| Cached principal projection / `CachedLogonProjection`, `CachedScalarLifecycle`, `PrincipalRefreshCache` | Absent/zero timestamp projection and high-level getter caches after underlying cache mutation/refresh | Source-backed candidates | Isolated lab for saved principals; staged timestamps are never committed; persisted timestamp-write semantics remain outside coverage |
| Native searcher/root ownership / `NativeSearcherReplacement`, `RetainedSearchRoot` | Context replacement and separate context/searcher disposal boundaries | Source-backed candidates | Isolated lab for initialization; initial root-read controls |
| Native projection/failure state / `NativeProjection`, `NativeFailureState` | Mapped attribute accumulation and temporary FindOne limit after failure | Source-backed candidates | Isolated lab; projection-growth controls and specifically proven missing-DN error |

## Validation

Run from the repository root with .NET SDK 10.0.401 (and the matching .NET 10
runtime). These Linux-safe commands build both Windows target frameworks but do
not execute a Microsoft DirectoryServices operation or create an AD fixture:

```sh
dotnet build tests/AdForLinux.DifferentialTests -c Release --nologo
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --list-tests --filter 'Category=CompatibilityCoverageOffline|Category=CompatibilityCoverageLive'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --list-tests --filter 'Category=CompatibilityCoverageOffline'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --list-tests --filter 'Category=CompatibilityCoverageLive'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --filter 'FullyQualifiedName~FixtureRegistrationTests'
dotnet test tests/AdForLinux.FunctionalTests -c Release -f net10.0 --filter 'FullyQualifiedName~DirectoryEntryLocalStateTests|FullyQualifiedName~CollectionCompatibilityTests'
git diff --check
```

The cloud validation used the executable `/tmp/adfl-dotnet/dotnet` with
`DOTNET_CLI_HOME=/tmp/adfl-cli`; these temporary paths are not prerequisites for
other machines. No full-suite `dotnet test` command is safe as an offline check.

Both differential target frameworks build with zero warnings/errors. Current
discovery reports 367 selected cases (366 new plus one enhanced existing case):
123 offline and 244 live selections.
The selected existing functional checks passed 27/27 again for batch 17. Current fixture
registration checks pass 22/22 without constructing AD fixtures. These checks
validate compilation/registration, not oracle parity.

The prior Windows results above apply to `789adbce`; the corrected batch needs a
new Windows run. No new workflow or AD run was dispatched for these corrections.
On Windows, the offline batch needs no credentials or AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net8.0-windows --filter 'Category=CompatibilityCoverageOffline' --logger 'trx;LogFileName=compatibility-offline-net8.trx'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --filter 'Category=CompatibilityCoverageOffline' --logger 'trx;LogFileName=compatibility-offline-net10.trx'
```

Only after verifying a disposable isolated AD lab and configuring the existing
fixture settings should `Category=CompatibilityCoverageLive` run. The fixture
creates and deletes all its entries, including computers, in its configured
`UsersContainer`. Verify the effective container including any
`AD_USERS_CONTAINER_DN` override; never use production or shared directories.
Do not run the entire suite as an offline
check. Keep net8.0-windows and net10.0-windows outcomes separate when reporting
failures, and preserve the Microsoft/clone observations from each failing case.

## Issue 215: portable option lifecycle (2026-10-04)

`Close()` now resets the retained configuration wrapper in place, so retained
`Options` references and subsequent `entry.Options` access share fresh state.
Path and credential/authentication changes also reset logical binding options.
Changing referral chasing only recreates the transport and preserves the other
options. New assignments after Close survive the next connection creation.

Fresh and reset security masks use `Owner | Group | Dacl`, as documented by
[ADS_SECURITY_INFO_ENUM](https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_security_info_enum).
Explicit mask assignments and validation/disposal ordering are preserved.

The existing Microsoft lifecycle comparisons are unchanged. The additional
`DirectoryEntryOptionDefaultsComparisonTests` class reads fresh Microsoft and
clone entries, creates independent Microsoft entries while another has modified
options, and checks two Close/rebind cycles. It writes observations to test output
and compares actual values, without hard-coded Microsoft defaults. Run it alone
in a fresh test process using
`--filter FullyQualifiedName~DirectoryEntryOptionDefaultsComparisonTests` on
each of `net8.0-windows` and `net10.0-windows`.

On Windows against the local Samba lab, both runtimes observed Microsoft PageSize
99 on fresh, independent and rebound entries, while the clone returned zero.
SecurityMasks passed on both runtimes. This isolates a remaining initial-default
gap from the fixed stale-value lifecycle bug. The portable no-paging default is
retained: these observations do not establish a provider-independent contract,
and no Windows ADSI dependency or observed numeric default was added.

The configured Windows AD endpoint failed binding with "The server is not
operational" on both runtimes, before either fresh-entry probe could read options.
The required existing lifecycle class and full Windows/AD differential suite
therefore remain unvalidated; Samba observations are not Windows/AD acceptance.
The 189 selected offline compatibility and fixture-registration cases passed on
each runtime. **Issue #215 remains open**, including the PageSize comparison and
the outstanding real-AD validation.

Linux/Samba validation used the existing test image, with the source copied into
the container to avoid overwriting Windows build outputs. The configured Samba
credentials were rejected, so validation used a temporary test administrator
instead of changing the existing administrator password; the temporary account
was deleted after validation. Each full run completed 542 cases:

| Linux runtime | Passed | Failed |
| --- | ---: | ---: |
| net8.0 | 469 | 73 |
| net10.0 | 541 | 1 |

All 19 option cases passed on each runtime, including the live Close/rebind
regression; an isolated net10.0 option run also passed 19/19. Every net8.0 failure
included LDAP server unavailability; a separate retry of
`ConnectionTests.Simple_bind_over_tls_succeeds` passed immediately. The net10.0
failure was `DirectorySearcherTests.FindAll_asynchronous_searches_are_repeatable_when_cached`.
It reported that the client-side timeout limit was exceeded.
These results do not establish a green full Linux suite; the full-suite failures
need separate investigation rather than being hidden by the focused results.
Detailed logs and per-runtime TRX files are retained locally under
`TestResults/issue215-*` (ignored build artifacts).
