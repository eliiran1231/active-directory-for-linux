# Compatibility coverage branch

Base: `dev` at `8023db6d6e63752420628a1ad94871f4dbe2edf0` (2026-10-01).
Only tests and their documentation are added. Microsoft System.DirectoryServices
9.0.0 is the runtime oracle; new cases do not prescribe guessed exception contracts.

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
| `CompatibilityContextlessSearcherComparisonTests` | 9 | Windows, no AD | Constructor versus assigned QueryFilter on contextless extension principals; FindOne/FindAll/underlying-searcher operations and disposal precedence |
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
distinguishes constructor initialization from QueryFilter assignment when an
extension principal lacks a context. These tests construct no PrincipalContext.

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

## Findings and prior-work check

All newly covered gaps remain **suspected/unconfirmed** until the Windows oracle
runs. Particularly useful probes are VLV arithmetic beyond small integer totals,
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

## Validation

On Linux with temporary .NET SDK 10.0.401:

```sh
dotnet build tests/AdForLinux.DifferentialTests -c Release
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --list-tests --filter 'Category=CompatibilityCoverageOffline|Category=CompatibilityCoverageLive'
dotnet test tests/AdForLinux.DifferentialTests -c Release -f net10.0-windows --no-build --filter 'FullyQualifiedName~FixtureRegistrationTests'
dotnet test tests/AdForLinux.FunctionalTests -c Release -f net10.0 --filter 'FullyQualifiedName~DirectoryEntryLocalStateTests|FullyQualifiedName~CollectionCompatibilityTests'
git diff --check
```

Both differential target frameworks build with zero warnings/errors. Current
discovery reports 353 selected cases (352 new plus one enhanced existing case):
121 offline and 232 live selections.
The selected existing functional checks passed 27/27 in batch 1. Current fixture
registration checks pass 22/22 without constructing AD fixtures. These checks
validate compilation/registration, not oracle parity.

Windows differential execution and live AD behavior are **unrun** here. On Windows,
the offline batch needs no credentials or AD settings:

```powershell
dotnet test tests/AdForLinux.DifferentialTests -c Release --filter 'Category=CompatibilityCoverageOffline' --logger 'trx;LogFilePrefix=compatibility-offline'
```

Only after verifying a disposable isolated AD lab and configuring the existing
fixture settings should `Category=CompatibilityCoverageLive` run. The fixture
creates and deletes all its entries, including computers, in its configured
`UsersContainer`. Verify the effective container including any
`AD_USERS_CONTAINER_DN` override; never use production or shared directories.
Do not run the entire suite as an offline
check. Keep net8.0-windows and net10.0-windows outcomes separate when reporting
failures, and preserve the Microsoft/clone observations from each failing case.
