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
  the internal lossless SID parser remains strict and unchanged. BA and WD aliases are covered.
- `AdForLinux.Security.AccessControl.AuthorizationRule`, `AccessRule`, `AuditRule`,
  `ObjectAccessRule`, `ObjectAuditRule`, `AuthorizationRuleCollection`: complete declared
  public/protected surface, validation precedence, propagation normalization, object GUID
  flag rules, retained identity values, indexing and collection copying.
- `GenericAce`, `KnownAce`, `QualifiedAce`, `CommonAce`, `ObjectAce`, `CompoundAce`,
  `CustomAce`: complete declared public/protected surface and concrete binary dispatch,
  mutable fields, opaque data, deep copy, equality and hash. The pinned .NET 9 MIT source
  and license are attributed. These detached API values retain native alias/copy behavior;
  they do not replace the immutable raw descriptor codec or edit shared descriptor storage.

The strict surface test compares all declared members of these 16 types, including exact
mapped dependency types, parameter names/order, protected accessibility, dispatch/sealing,
base/interface graph, properties/accessors and constants. It rejects unexpected additions
and missing members except the explicit three-entry SID staging list below. The recorded
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

There are **2,684 foundation observations per runtime**: 2,240 rule-constructor cases,
156 SID comparisons, 55 SID strings, 50 SID binary imports, 30 SID binary exports,
35 account construction/equality cases, 10 identity-target cases, 32 rule collection copies,
and 76 ACE cases. Every row is replayed on Linux. Metadata-only reflection records the
full surface separately; reflection does not prove behavior.

The runtimes have one measured behavior difference across eight rows:
`SecurityIdentifier.IsEqualDomainSid(null)` throws `ArgumentNullException("sid")` on .NET 8
and returns false on .NET 10. The portable target builds preserve this distinction on both
operating systems. Replay selects the corresponding runtime recording; a separate check
requires precisely those eight differences and equality of the other 2,676 rows.

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

The public `SecurityIdentifier(IntPtr)` constructor, `SecurityIdentifier(WellKnownSidType,
SecurityIdentifier)` constructor and `IsWellKnown(WellKnownSidType)` are not implemented.
The surface test names those exact gaps. Remaining SDDL SID aliases and unrecorded parser
combinations require implementation/evidence; matching the current cases is not complete
SID-string parity.

Cross-kind `IdentityReference.Translate(Type)` currently explicitly throws `NotSupportedException`
with a pending-resolver message. This is a foundation staging guard, **not the final resolver
exception contract or a new ambient-authentication policy**. It performs no lookup and derives
no authority from the value. The already approved context-bound resolver/ambient SID-to-name
policy still needs implementation. IdentityReferenceCollection and IdentityNotMappedException
also remain required dependencies; they have not been erased from the manifest.

The next implementation dependency is the portable ACL/descriptor closure: GenericAcl,
RawAcl, CommonAcl, DiscretionaryAcl, SystemAcl, AceEnumerator, GenericSecurityDescriptor,
RawSecurityDescriptor and CommonSecurityDescriptor, including all required constructors,
indexers, SDDL and mutation members. Continue with detached Windows contracts and immutable
raw/live/provenance reconciliation. Shared transaction gates and wrapper-local compatibility
locks/dirty flags are engineering details to implement and measure, not additional scope
choices for the user.

ObjectSecurity and DirectoryObjectSecurity then require the complete protected/public hooks,
sharing/lock/dirty-flag and dispatch behavior. The coherent AD cutover includes all nine rule
classes, ActiveDirectorySecurity, dependent consumers and fixtures in the same compiling
change. DirectoryEntry already has a Windows commit path: reviewed raw write preparation
must be wired before that cutover reaches it. Do not serialize projected observable bytes
as raw write bytes, silently disable existing behavior, or transfer resolver authority with
shared/cross-entry descriptor data. Existing AD classes and transport behavior remain unchanged
through this foundation stage. The standalone effective-access evaluator stays excluded.
