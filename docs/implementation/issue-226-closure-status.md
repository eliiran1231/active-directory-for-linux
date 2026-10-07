# Detached ACL, descriptor and SID closure status

This slice adds the nine supporting ACL/descriptor types to the existing
`AdForLinux.DirectoryServices` assembly under `AdForLinux.Security.AccessControl`:
`GenericAcl`, `RawAcl`, `CommonAcl`, `DiscretionaryAcl`, `SystemAcl`, `AceEnumerator`,
`GenericSecurityDescriptor`, `RawSecurityDescriptor` and `CommonSecurityDescriptor`.
The public SID adds its `WellKnownSidType`/domain constructor and `IsWellKnown`, together
with the measured static aliases. The strict manifest comparison now covers **25 types**.
Its only missing member within those mapped types is `SecurityIdentifier(IntPtr)`.
This is an implemented supporting slice, not completion of the full 55-type target.

The detached mutable types follow the recorded constructor, ownership, indexer, enumeration,
protection, purge, binary and supported SDDL contracts. Their Microsoft-style normalization
is separate from the immutable raw codec and mutation engine's preservation policy.
The existing AD hierarchy, resolver, DirectoryEntry transport and raw persistence preparation
are unchanged. This slice neither evaluates effective access nor performs directory writes.

## Recorded evidence and replay

The first closure probe is commit `c9ba866`; calibration is commit `bbb7249`.
`ClosureContracts.Write` writes a separate `--closure-json` artifact. The downloaded
[net8 recording](../research/acl-windows-oracle/results/closure-windows-net8.json)
and [net10 recording](../research/acl-windows-oracle/results/closure-windows-net10.json)
contain **2,224 byte-for-byte equivalent observation rows** on .NET 8.0.31 and 10.0.12,
using Microsoft System.DirectoryServices 9.0.0. Runtime metadata is retained separately.
The previous 2,692 foundation observations and 1,493 mutation observations remain unchanged.

| Recorded operation family | Rows | Exact successful outcomes | Exact native exceptions | Explicit portable refusals |
|---|---:|---:|---:|---:|
| Raw/common ACL constructors and behavior | 112 | 63 | 49 | 0 |
| Raw/common descriptor constructors and behavior | 119 | 102 | 17 | 0 |
| SDDL parse | 324 | 190 | 132 | 2 |
| SDDL round-trip | 328 | 187 | 132 | 9 |
| Host-relative SDDL semantics | 4 | 0 | 0 | 4 |
| SDDL binary formatting | 110 | 72 | 15 | 23 |
| SDDL exception-detail snapshots | 8 | 8 | 0 | 0 |
| Direct SID aliases | 130 | 100 | 30 | 0 |
| Binary SID `IsWellKnown` | 198 | 198 | 0 | 0 |
| Well-known SID construction | 396 | 325 | 71 | 0 |
| SID `IsWellKnown` | 495 | 495 | 0 | 0 |
| **Total** | **2,224** | **1,740** | **446** | **38** |

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

**38 recorded native successes deliberately require portable `NotSupportedException`.**
They are not counted as parity. Their registry pins exact case IDs, arguments, complete native
row hashes and reason counts; an unreviewed new shape cannot pass through a blanket exception
allowlist. Formatting refusals also verify that descriptor bytes remain unchanged.

| Reason | Rows |
|---|---:|
| Conditional-expression codec | 2 |
| Resource-attribute codec | 2 |
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

The focused closure/surface/cross-runtime/deferral suite passed **2,228 tests on each Linux
target**. The subsequent complete offline suite passed **7,282/7,282 on net8 and net10**,
with no skips, including the final native-row hash pins on both targets. The whole solution
build succeeded; its final incremental run reported zero warnings and zero errors after
local suppression of platform annotations on portable enum values. A clean test-project/CI
build still has seven pre-existing xUnit warnings per target, so the incremental result is
not a claim of a warning-free clean build.

These are measured local slice results, not claims about the final published head or its
Windows workflow. The Windows workflow requires committed closure, foundation, mutation
and surface baselines and compares fresh observations. Missing baselines fail the workflow.

Still staged: `SecurityIdentifier(IntPtr)`, `IdentityReferenceCollection`,
`IdentityNotMappedException`, context-bound cross-kind identity translation, `ObjectSecurity`,
`DirectoryObjectSecurity`, complete protected dispatch/lock/dirty-flag behavior, coherent
migration of ActiveDirectorySecurity and all nine AD rule classes, dependent consumers, and
reviewed raw write preparation. The required manifest retains every dependency. Unknown data,
raw provenance and no-write-on-read guarantees remain requirements for subsequent integration.
