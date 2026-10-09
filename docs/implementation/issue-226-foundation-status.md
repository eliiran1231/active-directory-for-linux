# Detached public foundation status — incomplete full-closure migration

Latest dependency: the [entry-bound resolver and raw-write preparation](issue-226-identity-context-status.md)
now provide explicit library-owned AD resolution, revocable wrapper binding and controlled
transport/lifecycle tests. Standalone identity values still carry no context. The historical
staging descriptions below do not supersede this implementation or authorize AD cutover.


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
and missing members within those 27 mapped types, including `SecurityIdentifier(IntPtr)`. The recorded
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

The public `SecurityIdentifier(IntPtr)` constructor now copies caller-owned SID storage
after native-order revision/count validation; 40 actual Windows rows cover invalid headers,
zero/one/fifteen subauthorities, unaligned addresses and detached ownership. The `WellKnownSidType`/domain-SID constructor and `IsWellKnown` are now
implemented with detached Windows replay. Measured static aliases are implemented; host-relative
LA/LG aliases are explicitly refused rather than deriving ambient authority. Unrecorded parser
combinations and deferred SDDL forms remain compatibility work, not implied full parity.

Cross-kind `IdentityReference.Translate(Type)` currently explicitly throws `NotSupportedException`
with a pending-resolver message. This is a foundation staging guard, **not the final resolver
exception contract or a new ambient-authentication policy**. It performs no lookup and derives
no authority from the value. The already approved context-bound resolver/ambient SID-to-name
policy still needs implementation. IdentityReferenceCollection and IdentityNotMappedException
now have detached implementations and complete public/protected surface checks. Their 85 native identity observations are now imported and replayed; see the
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

## Native identity and signed-SID follow-up — integrated evidence

The canonicalizer now uses unchecked signed subauthority subtraction, matching Microsoft's
SID comparison, including `S-1-5-4294967295` before `S-1-5-1`. IsWellKnown classifies native
values 95/96 as builtin RIDs 575/576 (RA/ES), with cross-pairs false. Classification remains
separate from the managed constructor's bound of 94.

`IdentityReferenceCollection` and `IdentityNotMappedException` implement the complete mapped
public/protected surface. Collection capacity/index/null/copy behavior follows the native
managed list contracts. Duplicates and object identities are retained; removal selects the
first equal value. The enumerator observes the live list by index, advances even on false
MoveNext, resets to -1 and has no-op Dispose. Empty/same-kind translation produces a new
collection retaining identity instances. Cross-kind translation retains the explicit pending
context-bound resolver refusal; forceSuccess does not convert missing resolver authority
into a native mapping-failure claim.

The mapping exception retains its inner exception, SystemException HResult, lazy mutable
UnmappedIdentities collection and base-only serialization metadata. No formatter or
deserialization is invoked. Cases 2314/2317 establish the runtime distinction: net8 uses the
CLR generic message naming the exception type; net10 uses the translation message. Replay
pins both exact messages, substitutes only the approved portable namespace in net8, and
compares every other field. Cross-runtime comparison requires precisely those two cases to
differ; all other 2,319 closure rows match exactly.

Implementation sources are the pinned MIT runtime
[IRCollection.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IRCollection.cs),
[net8 exception](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IdentityNotMappedException.cs),
and [later exception contract](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/IdentityNotMappedException.cs).
Attribution and the MIT license are retained. Surface comparison covers 27 mapped types;
the full 55-type target remains unchanged; the pointer follow-up closes the last SID member gap.

Actual Windows evidence from run 37737445450, source head d1845a412d505e359e7ca8c4b4bcf5c8f87dac67,
was imported in b168f636beb39fa4a49ad8f9f5547b5f6e0f5b46. These are retained **log-derived JSON
recordings**, not downloaded artifact ZIP bytes. The [provenance and checksums](../research/acl-windows-oracle/results/log-derived-37737445450-provenance.json)
record source jobs, timestamps, byte lengths, Git blob identities and SHA256 hashes. Local
verification confirms all four file hashes and that the previous 1,493 mutation/2,224 closure
rows are unchanged. The 2,692 foundation rows and required-surface recordings are unchanged.
Current totals per runtime: **1,845 mutation, 2,692 foundation and 2,321 closure observations**.

The additions are 352 mutation/live rows, 12 classifier rows and 85 identity rows. All are
replayed, not reconstructed. The retained-live harness covers **52 sequences / 516 steps**,
including every individual live row through its original import and preceding operations.
Unchecked signed SID comparison can be nontransitive: re-importing current live bytes can
reorder them again. The old isolated raw harness accidentally did that; it is no longer used
for retained-live rows. Tests preserve return/modified checks, raw/live bytes, intent,
contributor provenance and prior immutable snapshots. No production engine behavior was
changed to accommodate this test-harness correction.

The complete Linux offline suite contains **7,761 tests per target**, including the 18 focused
identity tests and 12 SID regressions. Build/CI details for the published checkpoint are kept
in the draft PR description; a passing replay alone is not fresh-native verification.
The first evidence-only Windows run 37828649371 exposed the stale count assertions and
incorrect raw re-import replay path; its recorder step was skipped. It is not a green result.

Next required dependencies: context-bound cross-kind translation, the 36 current explicit
SDDL limitations, ObjectSecurity/DirectoryObjectSecurity hooks/locks/dirty flags, and coherent
raw-safe retained-state/AD integration. Descriptor data carries no credentials, connections
or resolver authority. Existing AD classes, transport and preservation policy are unchanged.

## Conditional/resource and pointer checkpoint

The new [SDDL slice](issue-226-sddl-progress.md#conditionalresource-and-pointer-follow-up)
reduces the recorded refusal count from 38 to 35 and brings closure evidence to **2,564 rows
per runtime**. It adds 203 SDDL rows and 40 pointer rows. Native conditional/resource input,
canonical conditional output and pointer ownership now replay on both targets. The strict
surface test has no missing member among its 27 mapped types. This does not fill the rest
of the 55-type public/protected dependency closure. ObjectSecurity/DirectoryObjectSecurity,
context-bound resolution and coherent raw/live/provenance integration remain required.

The review follow-up raises current closure evidence to **3,268 rows**. It fixes conditional
NOT precedence, hash octets and measured name/escape lexical classes. Original refusals
remain reduced from 38 to 35, but native no-GUID ZA tail omission adds a newly discovered
loss boundary: **36 current refusals**. Its exact case, bytes and preservation behavior are
recorded in [SDDL progress](issue-226-sddl-progress.md#review-follow-up-precedence-name-grammar-and-native-za-tail).


## ObjectSecurity facade follow-up

The [measured facade implementation](issue-226-object-security-status.md) now adds ObjectSecurity
and DirectoryObjectSecurity, raising exact declared surface coverage to 29 types and closure
evidence to 3,517 rows. Shared descriptor mutations reconcile with retained raw/live/provenance
state, while locks, dirty flags and read contexts remain wrapper-local. One pinned invalid-enum
case preserves atomic rollback instead of native partial failure; all 36 SDDL refusals remain.
This completes the staged facade member slice, not the full AD hierarchy or transport cutover.
Context-bound identity resolution and reviewed raw write preparation remain the next dependencies.
