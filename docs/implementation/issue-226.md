# Internal ACL mutation engine — issue 226 draft

The implementation is internal only. It does not change public API, DirectoryEntry,
LDAP, identity resolution, the Microsoft interop boundary or any live-directory workflow.
Design evidence: PR #225 at ea0786fc3e75658732e7ac15a94134d54e24bf6c;
codec baseline: dev 339954545cea4d41f1b1b0c1d0c22961e35129f8;
issue comment 6025043919 supplies the trailing-payload and shared-storage requirements.

## Architecture

`AclMutationEngine` holds an immutable current `Descriptor`, the lossless
`OriginalDescriptor`, and section `WriteIntent`. Each call builds candidates in private
memory, validates the complete descriptor and only then returns a new engine. No-op and
failed calls retain the old value and create no new write intent. Microsoft return/modified
flags are separate operation evidence; they are not interpreted as byte changes or LDAP
write masks. All intent stays within retrieved sections.

`DescriptorRewriter` packs owner, group, SACL and DACL into independent storage, including
for equal or overlapping original offsets. It copies unedited components exactly. ACL
reserved fields and ACL trailing bytes survive edits. Unreferenced descriptor gaps or tails
are refused because no relocation policy has been established. Nothing edits shared bytes.

`MicrosoftObservableProjector` is a read-only projection. It implements only reviewed D13
normalizations: six recognized ACE families in the correct ACL kind, exact SID/GUID size,
known flags, inactive IO drop, NP clearing and explicit DACL object placement within the
same qualifier group. Inherited order is preserved. Original bytes and write intent remain
unchanged. NULL DACL getter projection is absent; owner/group/SACL changes in the raw engine
retain the original NULL representation.

## Implemented operations and evidence

- Add, Set, Reset, Remove, RemoveSpecific and RemoveAll dispatch for access/audit sections;
  explicit SID purge, owner/group replacement and protection changes.
  Detached protection preserves inherited flags/order when requested, as the new Windows
  recordings establish; removing inheritance drops the entries.
- Mask OR, complementary container scopes, same-shape audit success/failure merge;
  no merge across qualifier, object/non-object or distinct GUID shape.
- Remove splits remaining mask, audit and container propagation dimensions; returns false
  atomically for unrepresentable narrowing and true for no-match access removes.
- Object-specific subtraction qualifies only the measured DS rights; global rights still
  match across ObjectType GUIDs. Split ACEs drop inapplicable GUID fields while keeping
  their ACE family. Object Add/Set/Reset upgrades revision 2 to 4; common Add preserves it.
- Absent/NULL SACL removals return true with modified=false and no write intent.
- Set/Reset/Purge/RemoveAll keep inherited entries and target explicit SID/qualifier across GUIDs.
- Absent/NULL DACL materialization is DACL-operation-specific, preserving original raw state.

`AclMutationReplayTests` uses literal pinned Microsoft Windows outputs for B4/B6, C1–C3,
D1/D2, E1/E2, F1 and G1–G3, plus 300 newly recorded scripted steps including all audit
operation families and three-piece splits. I2 and J4/J6 projection tests assert exact
allowed results or explicit refusal of unapproved movement/loss. `MicrosoftObservableProjectorTests` exercises exact D13
predicates and raw/projection separation. `AclMutationEngineTests` checks atomic refusal,
unknown-data preservation outside changed ACLs, overlap, bounded sizes and deterministic
safe mask algebra. Existing codec/SID tests remain part of the explicit offline filter.

## Deferred and conservative boundaries

This draft does not claim completion of all issue 226 acceptance criteria.

- The I2 multi-entry SACL sorting policy is unresolved. Mutations with more than one existing
  explicit audit entry refuse before publication, except Set/Reset that replace every
  explicit audit for the same SID; simple single-entry merges/splits and replacements remain
  supported. No existing audit entries are silently sorted. Decreasing explicit SID order
  within an otherwise canonical subgroup also refuses instead of adopting unreviewed sorting.
- A changed ACL containing opaque/callback/unknown flags or recognized ACE trailing payload
  refuses as a whole. Owner/group or another section may still change while those bytes stay
  exact. This is intentionally narrower than Microsoft's H2 unrelated-add behavior.
- Full conditional ACE semantics, object-right-specific matching beyond the recorded shape
  cases (especially distinct InheritedObjectType subtraction), arbitrary OI propagation,
  duplicate-ACE import compaction and generalized normalization are not established
  by the current recordings. Active propagation combinations outside 0/2/3/6/10/14 refuse.
  Additional detached Windows recordings are required before expanding parity claims. No effective-access evaluator is claimed.
- Active zero-mask and audit-without-success/failure projection are refused; only the exact
  inactive D13 exception may drop them. Meaningful labels/audit entries never disappear.
- Descriptor gap/tail relocation, public exception/constructor parity and write-mask policy
  are outside the implemented evidence. This engine makes no DirectoryEntry rollback promise.

## Validation and Windows isolation

Only the five named fixture-free functional test classes run. The new workflow uses
`windows-2025`, ordinary GitHub-hosted runtime, .NET 8 and 10, `contents: read`, a push
trigger restricted to `bro/issue-226-acl-mutation-engine`, and TRX/oracle artifacts. It has
no AD secrets, environment, OU steps, privilege changes or Persist calls. Existing Samba
and self-hosted differential workflows are untouched.

The copied standalone oracle records detached Microsoft System.DirectoryServices 9.0.0
behavior. Successful process exit records execution, not parity; replay assertions supply
that evidence. Exact head validation and run URLs are reported in the draft PR.

The exact seeded recording provenance is documented in the oracle README. Tests replay actual Windows outputs on
both Linux and Windows, not generated expectations. The original J6 examples include
orphaned bytes after aliasing offsets, so those exact inputs refuse repacking; compact
shared-storage examples successfully unshare and preserve all referenced components.

Current offline filter: 413 mutation replay cases (including 300 recorded steps, sequence
replay and cross-runtime equality), 78 projection cases, 43 mutation safety cases, 139 codec
cases and 21 SID cases: 694 total. The safety suite includes 100 deterministic disjoint-mask
iterations (seed 2262026); projector predicates exhaust all 256 flag bytes across six types
and both ACL kinds. These iteration counts are not separate xUnit case counts.
