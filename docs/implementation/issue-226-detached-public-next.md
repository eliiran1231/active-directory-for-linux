# Detached-public transition — full required closure, staged implementation

The approved architecture remains one portable surface: supporting types in
`AdForLinux.Security.Principal` and `AdForLinux.Security.AccessControl`, inside the existing
main `AdForLinux.DirectoryServices` DLL. The nine AD rule classes and `ActiveDirectorySecurity`
keep their existing `AdForLinux.DirectoryServices` names. Framework enum types remain in use.
No implicit network resolution, conditional Windows-only public hierarchy, parallel AD API,
or new namespace/interop decision is proposed here.

Design baseline: PR225 `ea0786fc3e75658732e7ac15a94134d54e24bf6c`, especially
[protected hooks and facade discussion](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/acl-microsoft-interop-and-overrides.md#5-protected-hooks-preserve-extension-points-separate-native-defaults).
That decision preserves the hooks and explicitly states: “A constructor signature plus a
byte-only placeholder does not settle this.” The user subsequently confirmed the complete required public/protected dependency closure.
The [required-surface manifest](issue-226-required-surface.md) records that target; a bounded
subset is staging only, never the final compatibility contract.

The [internal Microsoft interop boundary](issue-226-interop-status.md) now stages data-only
snapshot provenance, strict detached round-trip validation, identity/rule/collection field
conversion, owner/group edit-back and unique-contributor ACL mask edits. Structural/ambiguous
ACL reconciliation and final public companion naming remain dependencies. The
[AD rule snapshot matrix](issue-226-ad-rule-interop-status.md) covers all nine current AD rule
types without switching their public hierarchy or claiming portable AD construction is complete.

## Recommended buildable sequence

1. Add immutable numeric identity values, the five rule bases and the rule collection in
   their approved supporting namespaces. Keep the existing AD classes unchanged during
   this foundation commit; there is no second set of AD rule classes. Constructor tests
   operate on the new foundations without Windows platform constructors or network work.
2. Implement the full required facade/member closure and its actual
   descriptor state and every mandatory protected hook. Probe native sharing, locking,
   dispatch and dirty-flag behavior before claiming compatibility.
3. Rebind all nine rule classes and `ActiveDirectorySecurity` together with dependent
   consumers and compile/reflection fixtures, in one compiling cutover. Switching the rules
   alone fails: the current BCL DirectoryObjectSecurity helpers
   and factory return types cannot accept portable rule bases. No BCL-rooted adapter or
   hidden replacement overload family should mask this dependency.
4. Validate that same cutover across the solution; consumer and fixture migration is part
   of step 3, not a later build-breaking commit. Keep the Microsoft oracle on pinned Microsoft
   types. Public binary/SDDL setters, enumeration and identity
   access are obligations of the eventual switch; unsupported implementation cannot be
   hidden behind matching signatures. Directory transport changes remain a separate phase.

## Identity and rule contract

The bounded numeric identity implementation uses the existing immutable SID core for numeric
string and byte-array/offset construction, defensive binary export, canonical value,
equality/hash and numeric ordering. IdentityReference must supply the approved hierarchy
and target-type contract. NTAccount, where required as a value dependency, remains an
unresolved name value: construction never performs LDAP, OS account lookup or translation.
Translation behavior needing a resolver must use the agreed explicit boundary. This is not
an assertion that every BCL SecurityIdentifier constructor family is already implemented.

Implement AuthorizationRule, AccessRule, AuditRule, ObjectAccessRule, ObjectAuditRule and
AuthorizationRuleCollection. Preserve the following nine AD rule classes and **45 public
constructors**, plus the descriptor class's public default constructor:

| Rule class | Public constructors |
| --- | ---: |
| ActiveDirectoryAccessRule | 6 |
| ActiveDirectoryAuditRule | 6 |
| CreateChildAccessRule | 6 |
| DeleteChildAccessRule | 6 |
| ExtendedRightAccessRule | 6 |
| PropertyAccessRule | 6 |
| ListChildrenAccessRule | 3 |
| DeleteTreeAccessRule | 3 |
| PropertySetAccessRule | 3 |

Retain each overload's parameter order and derived rights mask. Directed Windows recordings
must establish null/enum/mask validation precedence, exception type/parameter, nonzero masks,
identity retention, arbitrary rights-bit handling and all GUID/inheritance combinations.
Constructor normalization is distinct from raw ACE interpretation: propagation is cleared
when inheritance is absent; object GUID presence depends on a nonempty GUID and applicable
object-qualified rights; inherited GUID presence requires container inheritance. Verify the
exact predicates and validation order instead of applying them to existing raw ACE bytes.

The AD inheritance mapping to probe is None, All, Descendents, SelfAndChildren and Children,
including invalid enum values and the corresponding container/IO/NP flags. All 45 overloads
need compile coverage plus behavioral cases; use the existing pinned Microsoft9 recorder and
explicit fixture-free test filters on Linux/Windows .NET8/10.

## Mandatory protected descriptor-facade contract

These hooks are already required. They are not optional merely because current wrapper
methods use only a subset. Types below refer to portable supporting types except the
existing framework enums and SafeHandle.

- AuthorizationRule: protected-internal `(IdentityReference, int accessMask, bool isInherited,
  InheritanceFlags, PropagationFlags)` constructor and protected-internal AccessMask getter.
- AccessRule/AuditRule: protected constructors adding AccessControlType/AuditFlags.
- ObjectAccessRule/ObjectAuditRule: protected constructors with identity, mask, inherited,
  inheritance flags, propagation flags, **object GUID, inherited GUID, then access/audit kind**.
- ObjectSecurity: protected `()`, `(bool isContainer, bool isDS)`, and
  `(CommonSecurityDescriptor)` constructors. DirectoryObjectSecurity: protected `()` and
  `(CommonSecurityDescriptor)` constructors.
- ObjectSecurity exposes protected **nonvirtual get-only properties**
  `CommonSecurityDescriptor SecurityDescriptor`, `bool IsContainer`, `bool IsDS`.
  Preserve the four protected get/set flags OwnerModified, GroupModified,
  AccessRulesModified and AuditRulesModified.
- Preserve protected ReadLock/ReadUnlock/WriteLock/WriteUnlock, recursive access discipline,
  correct wrapper-local ownership checks and exception-safe release.
- Preserve protected abstract `bool ModifyAccess(AccessControlModification, AccessRule,
  out bool modified)` and the corresponding AuditRule hook. DirectoryObjectSecurity
  supplies protected, nonsealed overrides.
- Preserve protected **nonvirtual** access Add/Set/Reset/Remove/RemoveAll/RemoveSpecific
  helpers and audit Add/Set/Remove/RemoveAll/RemoveSpecific helpers. There is no invented
  ResetAuditRule helper. Dispatch must follow measured native paths rather than routing
  every typed helper through every public override.
- Preserve protected virtual Persist overloads `(string, AccessControlSections)`,
  `(bool, string, AccessControlSections)`, and `(SafeHandle, AccessControlSections)`.
  These are extension points, not implicit LDAP persistence. The false-valued forwarding
  path and unsupported base paths require exact detached tests.

Factories are **public**, not protected: ordinary ObjectSecurity factories are abstract;
DirectoryObjectSecurity's object-GUID factories are virtual, not abstract; the concrete AD
class seals all four overrides. Factory arguments put access/audit kind **before** the two
GUIDs, unlike object-rule constructors. Preserve public virtual modify/purge dispatch and
AccessRightType/AccessRuleType/AuditRuleType as well.

## Facade implementation requirements

Implement this foundation and the remaining full manifest before the AD cutover:

- CommonSecurityDescriptor binary/offset construction `(bool isContainer, bool isDS,
  byte[] binaryForm, int offset)`; stable container/DS identity, revision/control flags,
  owner/group, binary length/export and canonicality/protection inspection.
- Usable portable DACL/SACL facades with assignment, direct rule mutation, purge and
  inherited-entry handling. Their complete member signatures are enumerated by the required-surface recorder. A descriptor that exposes only bytes is insufficient.
- Every direct edit routes through the atomic core and its retained live/provenance model.
  Observable bytes and raw write bytes remain separate; new import is explicit. Failed
  edits preserve all state, no-op edits create no write intent, and layout restrictions
  continue to apply.
- Preserve supplied-facade reference identity. Use a shared internal mutation gate for
  facade transactions **plus wrapper-local compatibility lock discipline**. Native locks
  belong to each ObjectSecurity wrapper, not to the shared descriptor. Wrapper A holding
  a lock must not authorize wrapper B's protected dirty-flag access.
- Keep wrapper-local original/read context, retrieved-section restrictions, resolver
  authority and persistence intent separate. Direct facade changes notify an independent
  mutation ledger; they do not automatically set every wrapper's native-style protected
  dirty flags. Descriptor sharing never transfers resolver/credential authority.

The synchronization/notification additions are a proposed safety contract, not a claim of
native parity. Detached probes should measure supplied-object sharing, getter identity,
external owner/group/ACL changes, dirty flags, recursive/cross-wrapper locking, cleanup,
typed-helper dispatch, ACL assignment aliasing and indexer snapshot behavior. Microsoft
behavior is to be measured, not selected by user preference.

**Resolved scope:** implement the complete required dependency closure, including indexers,
SDDL and required raw descriptor/ACL constructors. The member manifest is an implementation
and validation checklist, not another user scope choice. Shared mutation gates and notification
ledgers are internal engineering choices to validate against measured sharing, locks and dirty
flags, with resolver authority isolation. No full-compatibility claim is made for this foundation
stage; explicit pending members are recorded in the foundation status. Namespace, packaging,
protected-hook preservation and the single-surface architecture remain settled.

## Existing build dependencies

DirectoryEntry needs its internal `(byte[], SecurityMasks)` loader, RetrievedMasks,
IsModified and binary export to keep compiling. Its existing Windows gate already enables a commit path. Before the cutover reaches that
path, wire reviewed raw write preparation; serializing observable bytes can violate preservation.
Keep the foundation unwired until that dependency is satisfied, without silently disabling
existing functionality. Principal.Sid must move to the approved portable SID value;
keep SidValue and update platform-specific documentation. Differential tests with BCL SID/
rule-base variables need explicit portable substitutions, not broad name-normalizing
reflection. Keep native-oracle argument types separate from portable replay types.


## ObjectSecurity facade follow-up

The [measured facade implementation](issue-226-object-security-status.md) now adds ObjectSecurity
and DirectoryObjectSecurity, raising exact declared surface coverage to 29 types and closure
evidence to 3,517 rows. Shared descriptor mutations reconcile with retained raw/live/provenance
state, while locks, dirty flags and read contexts remain wrapper-local. One pinned invalid-enum
case preserves atomic rollback instead of native partial failure; all 36 SDDL refusals remain.
This completes the staged facade member slice, not the full AD hierarchy or transport cutover.
The next [context resolver/raw-preparation dependency](issue-226-identity-context-status.md) now
has a staged implementation and controlled tests. Public commit-mask/Add choices, the
The [internal PrincipalContext adapter](issue-226-principal-identity-status.md) is implemented; its
public exposure and coordinated AD transport cutover remain outstanding.
