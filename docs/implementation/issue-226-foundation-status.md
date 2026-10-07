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

The original foundation contained 16 types. The ACL/descriptor follow-up adds nine, so the
strict surface test now compares all declared members of 25 types, including exact
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
also remain required dependencies; they have not been erased from the manifest.

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
