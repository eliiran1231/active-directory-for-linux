# Detached ACL, descriptor and SID closure status

Latest codec evidence: [FL representation follow-up](issue-226-sddl-progress.md#access-filter-fl-representation-follow-up)
adds 719 measured rows, bringing closure to 4,308. Counts in earlier slice sections below are
historical. Current accounting: 2,855 exact successes, 1,250 exact exceptions, 154 explicit SDDL
refusals, eight facade preservation refusals and 41 atomic-failure differences. No class is
certified complete by these counts.

Current readiness: [end-to-end inventory](issue-226-remaining-compatibility.md). The portable
AD/entry cutover and public MicrosoftInterop companion are implemented. Descriptions below
of them as future work are historical slice boundaries, not current missing dependencies.
Historical counts are not the latest whole-PR validation or a claim of complete behavior.

Current integration: [portable public AD cutover and raw persistence](issue-226-entry-persistence-status.md)
supersedes the historical staging statements below about the BCL-rooted AD hierarchy and
unwired DirectoryEntry path. Historical oracle counts and preservation boundaries remain evidence,
not claims of live-directory parity.

Latest measured checkpoint: **3,589 closure rows**, including 321 ObjectSecurity/facade rows,
and **29 mapped supporting types**. The NULL-DACL rollback correction adds 72 native rows
without changing the preceding 3,517; 40 failures deliberately preserve atomic rollback,
while all 32 new successful edits/protection calls require exact parity. See
[facade evidence and accounting](issue-226-object-security-status.md#nullabsent-dacl-transaction-correction).
The earlier slice inventories below retain their historical counts.

This slice adds the nine supporting ACL/descriptor types to the existing
`AdForLinux.DirectoryServices` assembly under `AdForLinux.Security.AccessControl`:
`GenericAcl`, `RawAcl`, `CommonAcl`, `DiscretionaryAcl`, `SystemAcl`, `AceEnumerator`,
`GenericSecurityDescriptor`, `RawSecurityDescriptor` and `CommonSecurityDescriptor`.
The public SID adds its `WellKnownSidType`/domain constructor and `IsWellKnown`, together
with the measured static aliases. The identity follow-up brings the strict manifest comparison to **27 types**; see
[foundation status](issue-226-foundation-status.md#native-identity-and-signed-sid-follow-up--integrated-evidence).
All declared members within those mapped types, including `SecurityIdentifier(IntPtr)`, are implemented.
This is an implemented supporting slice, not completion of the full 55-type target.

The detached mutable types follow the recorded constructor, ownership, indexer, enumeration,
protection, purge, binary and supported SDDL contracts. Their Microsoft-style normalization
is separate from the immutable raw codec and mutation engine's preservation policy.
The existing AD hierarchy, resolver, DirectoryEntry transport and raw persistence preparation
are unchanged. This slice neither evaluates effective access nor performs directory writes.

## Recorded evidence and replay

The first closure probe is commit `c9ba866`; calibration is commit `bbb7249`.
`ClosureContracts.Write` writes a separate `--closure-json` artifact. The checked-in
[net8 recording](../research/acl-windows-oracle/results/closure-windows-net8.json)
and [net10 recording](../research/acl-windows-oracle/results/closure-windows-net10.json)
contain **3,268 observation rows** on .NET 8.0.31 and 10.0.12,
using Microsoft System.DirectoryServices 9.0.0. Runtime metadata is retained separately.
The previous 2,224 closure rows are unchanged. The only cross-runtime differences are
null-message IdentityNotMappedException cases 2314/2317; exact runtime-aware assertions check
both messages and every remaining field. Current mutation evidence has 1,845 rows; the 2,692
foundation rows remain unchanged. Updated files are log-derived; [provenance](../research/acl-windows-oracle/results/log-derived-37737445450-provenance.json)
pins their origin and hashes, rather than claiming original artifact ZIP bytes.

| Recorded operation family | Rows | Exact successful outcomes | Exact native exceptions | Explicit portable refusals |
|---|---:|---:|---:|---:|
| Raw/common ACL constructors and behavior | 112 | 63 | 49 | 0 |
| Raw/common descriptor constructors and behavior | 119 | 102 | 17 | 0 |
| SDDL parse | 789 | 442 | 347 | 0 |
| SDDL round-trip | 761 | 421 | 331 | 9 |
| Host-relative SDDL semantics | 4 | 0 | 0 | 4 |
| SDDL binary formatting | 110 | 72 | 15 | 23 |
| SDDL exception-detail snapshots | 17 | 17 | 0 | 0 |
| Direct SID aliases | 130 | 100 | 30 | 0 |
| Binary SID `IsWellKnown` | 202 | 202 | 0 | 0 |
| Well-known SID construction | 396 | 325 | 71 | 0 |
| SID `IsWellKnown` | 503 | 503 | 0 | 0 |
| Identity collections | 77 | 32 | 45 | 0 |
| Mapping exception/serialization metadata | 8 | 7 | 1 | 0 |
| SID pointer import | 40 | 6 | 34 | 0 |
| **Total** | **3,268** | **2,292** | **940** | **36** |

An exception-detail snapshot is a successful recorder operation whose payload describes the
exception actually thrown by a native SDDL operation, including its native error code.
“Successful outcome” does not imply every boolean outcome is true. Native exception parity
checks both the exception type and argument parameter, where applicable.

The SID cases cover enum integers -1 through 96 plus 999, null/domain/account/builtin domain
arguments, logon and domain-relative identities, and the binary roots needed to distinguish
unsupported constructors from classification. Static tables contain 75 measured well-known
values, 17 relative RIDs and 50 case-insensitive aliases. Direct alias probes exclude LA/LG:
those require host authority and are recorded separately, without an ambient portable lookup.

## Explicit SDDL limitations

**36 recorded native successes deliberately require portable `NotSupportedException`.**
They are not counted as parity. Their registry pins exact case IDs, arguments, complete native
row hashes and reason counts; an unreviewed new shape cannot pass through a blanket exception
allowlist. Formatting refusals also verify that descriptor bytes remain unchanged.

| Reason | Rows |
|---|---:|
| Native omission of resource attributes on formatting | 1 |
| Native omission of collapsed ZA callback tail on formatting | 1 |
| Native omission of label/policy entries on formatting | 3 |
| Host-relative LA/LG aliases | 8 |
| Native omission of opaque bytes or flag information on formatting | 23 |

The four `SddlHostRelative` rows record actual native RID, `IsWellKnown`, domain-presence and
canonical round-trip properties. Their output excludes the host machine SID, which varied
across runner machines. The other four LA/LG rows record literal round-trip strings. Portable
code refuses all eight rather than guessing a machine or domain identity. This narrow
recorder change is not a general normalization of arbitrary native output.

Supported SDDL includes measured ordinary/object ACE forms, accepted audit contexts and
rejected alarm/context combinations, rights masks, GUIDs, ACL flags and static aliases.
See [SDDL progress](issue-226-sddl-progress.md) for the exact supported and refused forms. These observations do not establish complete
conditional/resource SDDL support or permission to discard opaque binary data.

## Verification and remaining work

The original ACL/descriptor slice's focused closure/surface/cross-runtime/deferral suite passed **2,228 tests on each Linux
target**. The subsequent complete offline suite passed **7,282/7,282 on net8 and net10**,
with no skips, including the final native-row hash pins on both targets. The whole solution
build succeeded; its final incremental run reported zero warnings and zero errors after
local suppression of platform annotations on portable enum values. A clean test-project/CI
build still has seven pre-existing xUnit warnings per target, so the incremental result is
not a claim of a warning-free clean build.

The integrated identity/signed-SID suite now contains **7,761 offline tests per runtime**;
the draft PR records the latest exact-head execution results.

These are measured local slice results, not claims about the final published head or its
Windows workflow. The Windows workflow requires committed closure, foundation, mutation
and surface baselines and compares fresh observations. Missing baselines fail the workflow.

Still staged: context-bound cross-kind identity translation, `ObjectSecurity`,
`DirectoryObjectSecurity`, complete protected dispatch/lock/dirty-flag behavior, coherent
migration of ActiveDirectorySecurity and all nine AD rule classes, dependent consumers, and
reviewed raw write preparation. The required manifest retains every dependency. Unknown data,
raw provenance and no-write-on-read guarantees remain requirements for subsequent integration.

The conditional/resource follow-up adds 243 actual observations (203 SDDL and 40 pointer)
without changing the previous 2,321. [Current provenance](../research/acl-windows-oracle/results/log-derived-37832226853-provenance.json)
pins runs 37831311746 and 37832226853. The only runtime differences remain cases 2314/2317.
The [SDDL inventory](issue-226-sddl-progress.md) now fixes 35 refusals: 27 native lossy exports
and eight host-authority aliases. Three earlier codec refusals are resolved; none were
converted into skipped assertions. All new rows require native parity.

Review probes add another 704 SDDL rows, bringing closure evidence to 3,268. The original
35 remaining refusals persist; newly discovered case 2635 adds one loss-preserving refusal,
so the current total is 36. [Details and exact byte counts](issue-226-sddl-progress.md#review-follow-up-precedence-name-grammar-and-native-za-tail)
explain native ZA tail omission. [Current provenance](../research/acl-windows-oracle/results/log-derived-37840983666-provenance.json)
records the actual source logs. Negation precedence, hash octets, local/prefixed name classes
and percent escapes now have directed native regression coverage.


## ObjectSecurity facade follow-up

The [measured facade implementation](issue-226-object-security-status.md) now adds ObjectSecurity
and DirectoryObjectSecurity, raising exact declared surface coverage to 29 types and closure
evidence to 3,517 rows. Shared descriptor mutations reconcile with retained raw/live/provenance
state, while locks, dirty flags and read contexts remain wrapper-local. One pinned invalid-enum
case preserves atomic rollback instead of native partial failure; all 36 SDDL refusals remain.
This completes the staged facade member slice, not the full AD hierarchy or transport cutover.
Context-bound identity resolution and reviewed raw write preparation remain the next dependencies.
