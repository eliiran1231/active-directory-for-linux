# Detached public foundation status — incomplete full-closure migration

This stage adds supporting types in the already approved namespaces inside the existing
`AdForLinux.DirectoryServices` DLL. It does **not** switch the existing AD classes, create a
parallel AD API, wire LDAP, resolve names, persist anything or implement an access evaluator.
The target is the complete required public/protected closure, recorded in
[the required-surface manifest](issue-226-required-surface.md). Missing types and members
below are staging dependencies, not approved permanent omissions.

## Implemented foundation

- `AdForLinux.Security.Principal.IdentityReference`, `SecurityIdentifier`, `NTAccount`:
  immutable numeric SID/binary values, defensive copies, value comparison/hash, domain
  inspection/comparison, unresolved account names, target-type checks and same-type
  translation. Numeric public parsing follows measured Windows conversion behavior while
  the internal lossless SID parser remains strict and unchanged. The closure follow-up adds
  measured well-known/domain SID construction, classification and 50 static aliases; see
  [closure status](issue-226-closure-status.md).
- `AdForLinux.Security.AccessControl.AuthorizationRule`, `AccessRule`, `AuditRule`,
  `ObjectAccessRule`, `ObjectAuditRule`, `AuthorizationRuleCollection`: complete declared
  public/protected surface, validation precedence, propagation normalization, object GUID
  flag rules, retained identity values, indexing and collection copying.
- `GenericAce`, `KnownAce`, `QualifiedAce`, `CommonAce`, `ObjectAce`, `CompoundAce`,
  `CustomAce`: complete declared public/protected surface and concrete binary dispatch,
  mutable fields, opaque data, deep copy, equality and hash. The pinned .NET 9 MIT source
  and license are attributed. These detached API values retain native alias/copy behavior;
  they do not replace the immutable raw descriptor codec or edit shared descriptor storage.

The original foundation contained 16 types. The ACL/descriptor follow-up adds nine and the
identity collection/exception follow-up adds two, so the
strict surface test now compares all declared members of 27 types, including exact
mapped dependency types, parameter names/order, protected accessibility, dispatch/sealing,
base/interface graph, properties/accessors and constants. It rejects unexpected additions
and missing members except the explicit `SecurityIdentifier(IntPtr)` staging gap below. The recorded
full target has 39 roots, 55 types, 702 declaration records and 28 framework boundaries.
The shared framework enums remain framework types.

## Actual Windows evidence

The detached recorder is pinned to Microsoft System.DirectoryServices 9.0.0. The first
[foundation probe](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37686047464),
head `6b07c23622974d4a09382f54d0dee64946cd0bc1`, recorded 2,554 cases and the complete surface.
The [boundary probe](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37686708031),
head `549a38c8c1a2b367559e5ab2b765bf2aaf56e1ed`, adds 130 SID parser/domain boundary cases;
all preceding observations are unchanged for each runtime. Both probes preserve the previous
1,493 mutation observations. The checked-in JSON files are the downloaded artifact bytes.

There are **2,692 foundation observations per runtime**: 2,240 rule-constructor cases,
156 SID comparisons, 55 SID strings, 50 SID binary imports, 30 SID binary exports,
35 account construction/equality cases, 10 identity-target cases, 32 rule collection copies,
76 ACE cases and eight repeated-domain identity cases. Every row is replayed on Linux. Metadata-only reflection records the
full surface separately; reflection does not prove behavior.

The runtimes have one measured behavior difference across eight rows:
`SecurityIdentifier.IsEqualDomainSid(null)` throws `ArgumentNullException("sid")` on .NET 8
and returns false on .NET 10. The portable target builds preserve this distinction on both
operating systems. Replay selects the corresponding runtime recording; a separate check
requires precisely those eight differences and equality of the other 2,684 rows.

Examples established by actual Windows execution:

- Zero-subauthority SIDs are valid binary values but invalid SDDL strings.
- Public SID numeric parsing accepts hexadecimal components and saturates oversized
  subauthorities at UINT_MAX; the internal raw SID parser does not adopt this conversion.
- Invalid parsed revisions and excessive subauthority counts report `binaryForm`, while
  textual syntax/range failures report `sddlForm` in the measured cases.
- Account-domain SIDs use NT authority and the 21 prefix with at least four subauthorities;
  builtin 32-prefix identities can compare as equal-domain without being account SIDs.
- Constructor validation, GUID/mask/inheritance normalization, collection bounds and ACE
  opaque alias versus deep-copy behavior match the recorded native outcomes.

## Exact remaining dependencies

The public `SecurityIdentifier(IntPtr)` constructor remains unimplemented and is the exact
SID surface gap. The `WellKnownSidType`/domain-SID constructor and `IsWellKnown` are now
implemented with detached Windows replay. Measured static aliases are implemented; host-relative
LA/LG aliases are explicitly refused rather than deriving ambient authority. Unrecorded parser
combinations and deferred SDDL forms remain compatibility work, not implied full parity.

Cross-kind `IdentityReference.Translate(Type)` currently explicitly throws `NotSupportedException`
with a pending-resolver message. This is a foundation staging guard, **not the final resolver
exception contract or a new ambient-authentication policy**. It performs no lookup and derives
no authority from the value. The already approved context-bound resolver/ambient SID-to-name
policy still needs implementation. IdentityReferenceCollection and IdentityNotMappedException
now have detached implementations and complete public/protected surface checks. Their new
85-row native replay remains pending import of the original recorded evidence; see the
identity follow-up below.

The portable ACL/descriptor supporting closure is now implemented and compared against the
full declared shape for GenericAcl, RawAcl, CommonAcl, DiscretionaryAcl, SystemAcl, AceEnumerator,
GenericSecurityDescriptor, RawSecurityDescriptor and CommonSecurityDescriptor. Its separate
2,224-row recording and 38 explicit SDDL refusals are described in
[closure status](issue-226-closure-status.md). Those detached mutable facade contracts do not
replace immutable raw/live/provenance reconciliation or authorize projected bytes for persistence.

ObjectSecurity and DirectoryObjectSecurity then require the complete protected/public hooks,
sharing/lock/dirty-flag and dispatch behavior. The coherent AD cutover includes all nine rule
classes, ActiveDirectorySecurity, dependent consumers and fixtures in the same compiling
change. DirectoryEntry already has a Windows commit path: reviewed raw write preparation
must be wired before that cutover reaches it. Do not serialize projected observable bytes
as raw write bytes, silently disable existing behavior, or transfer resolver authority with
shared/cross-entry descriptor data. Existing AD classes and transport behavior remain unchanged
through this foundation stage. The standalone effective-access evaluator stays excluded.

## Foundation review follow-up

The [repeated-domain probe](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37688432355),
head `d374b0112a33cb9ded30277f8ff4e0aa6ff11ff4`, adds eight observations on both runtimes.
All preceding 2,684 cases are unchanged. It confirms repeated AccountDomainSid reads return
one cached object, distinct from the input SID, for account/domain identities, with or without
an earlier IsAccountSid call. The portable property now publishes one cached immutable domain
SID; non-account identities continue returning null. The probe intentionally fails freshness
against the preceding committed baseline; its artifacts supply the new evidence.

Rule replay now reads each constructed probe's actual protected AccessMask, including audit
and object-qualified rules and collection copies; it no longer echoes the requested mask.
A temporary local corruption of stored AccessMask was detected by 780 recorded rule/collection
rows, then reverted before the passing suite. The case-ID assertion removes the foundation's
xUnit1026 warning. Seven existing xUnit2013 warnings in CollectionCompatibilityTests,
DirectoryEntryReadTests and GroupPrincipalTests remain on a clean test-project build. The
previous zero-warning solution result was an incremental local build, not a warning-free
clean Windows build; no directory-dependent tests were run to change those fixtures.

## Recovery follow-up — 2026-10-08

Starting from verified published head `d1845a412d505e359e7ca8c4b4bcf5c8f87dac67`,
the internal canonicalizer now compares subauthorities using unchecked signed subtraction,
matching the existing portable SID comparison. In particular, `S-1-5-4294967295` sorts before
`S-1-5-1`. Focused DACL/SACL tests verify both input orders, unchanged ACE contents and
unchanged raw ACL bytes. `IsWellKnown` now classifies native values 95 and 96 as builtin RIDs
575 (RA) and 576 (ES), respectively; cross-pairs remain false. These classification-only
values do not extend the managed constructor's upper bound of 94.

Linux Release offline validation passes **7,294 tests per target** on .NET 8 and 10, with
zero failures/skips. A full solution rebuild succeeds with the existing seven xUnit2013
warnings per target. Twelve added regressions supplement the existing committed recordings;
they do not replace fresh native evidence or claim full dependency closure.

The recovery environment could list Windows run `37737445450` artifacts 11532172439 (net8)
and 11532720752 (net10) through the authorized GitHub connector, but downloading the
connector-provided file URLs returned HTTP 403, including a reviewed retry. Thus this change
does **not** import or reconstruct those recordings. The committed baselines still contain
1,493 mutation, 2,692 foundation and 2,224 closure rows. The push workflow's strict freshness
comparison is expected to remain blocked by the unimported new observations.

The next required identity work remains `IdentityReferenceCollection` and
`IdentityNotMappedException`, replay of the 85 newly reported identity rows, and exact
runtime-aware assertions for closure cases 2314/2317 (null-message constructors). Their
reported net8 generic type-name message versus net10 translation message must be verified
from the original recordings; blanket cross-runtime equality must not replace that contract.
The 352 new mutation/live rows and 12 classifier rows also await artifact import. SDDL's
38 explicit refusals, SID IntPtr, context-bound translation, ObjectSecurity and
DirectoryObjectSecurity, retained-state facade integration and coherent AD/raw-safe cutover
remain incomplete. No AD class, transport, resolver authority or preservation policy changed.


## Identity collection/exception follow-up — local, native replay import blocked

`IdentityReferenceCollection` and `IdentityNotMappedException` are implemented as detached
supporting types. Collection capacity/index/null/copy behavior delegates to the same managed
list contracts as Microsoft. Duplicate values and object identity remain intact; removal
selects the first equal value. The enumerator observes the live list by index, advances even
on a false MoveNext, resets to -1, and has no-op Dispose. Same-kind and empty translation
return new collections retaining existing identity instances. Cross-kind translation retains
the existing explicit pending-resolver NotSupportedException, independently of forceSuccess;
this is a documented staging refusal, not the final native mapping exception contract.

The mapping exception retains inner exceptions, SystemException's HResult, one lazy mutable
UnmappedIdentities collection per instance, and base-only metadata serialization. A null
message follows the target runtime: net8 delegates to the CLR's generic message naming the
portable exception type; net10 supplies the translation message. An explicit empty message
stays empty. No formatter or deserialization was executed.

Implementation sources are the pinned MIT runtime
[IRCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IRCollection.cs),
[net8 exception](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IdentityNotMappedException.cs),
and [later exception contract](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IdentityNotMappedException.cs).
Attribution and MIT license are retained. The strict manifest now covers 27 mapped types,
with only the previously explicit SID IntPtr gap within those types. The full 55-type target
is unchanged.

Eighteen focused source-contract tests were added. The complete Linux offline suite passes
**7,312 tests per runtime**, no failures/skips, and the full solution builds. These tests are
separate from the pending 85 actual native rows. The replay dispatch supports all ten native
identity operation families. Runtime-aware comparisons for cases 2314/2317 pin each exact
native/portable message and compare every other field, rather than discarding all messages or
requiring blanket runtime equality. Those two recording branches are not yet exercised by
the committed 2,224-row closure baseline; its count is deliberately unchanged until import.

The reviewer supplied retained log-derived evidence for run 37737445450 through Library,
archive SHA256 `90fa44e839b776946bb31fb70ff9252a5acb6c548d3078a3793bedce3d1907ca`.
The supported resolved-reference materialization route resolved the file, but both the first
consumer-local transfer and the one permitted retry returned `download failed`, without an
HTTP status or response body. No local archive was produced; archive/per-file hashes could
not be checked. No denied artifact endpoint or authentication route was retried. No baseline
was reconstructed. A successful future import must label these bytes as log-derived JSON,
not original downloaded ZIP contents, and validate provenance and all supplied hashes.

Next: import and replay the retained native evidence, then verify an exact-head Windows
checkpoint. The 38 explicit SDDL limitations, SID IntPtr, context-bound translation,
ObjectSecurity/DirectoryObjectSecurity hooks and the raw-safe retained-state/AD cutover remain
required, incomplete work. These collection/exception values carry no resolver credentials,
connections, or authority. Existing AD classes, transport and preservation policy are unchanged.
