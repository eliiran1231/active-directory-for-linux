# Internal ACL mutation engine — issue 226 draft

See the [morning review acceptance matrix](issue-226-acceptance-matrix.md) for requirement-by-requirement status and the measured three-stage Add algorithm and remaining parity boundaries. The [ordering/projection policy](issue-226-ordering-policy.md) records the newly approved slice.

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
write masks. All intent stays within retrieved sections. Incoming ACEs represent effective constructed
Microsoft rule shapes. Object rules with no GUID flags are refused rather than guessed;
such ACEs remain valid existing raw data and do not match a common RemoveSpecific rule.

`DescriptorRewriter` packs owner, group, SACL and DACL into independent storage, including
for equal or overlapping original offsets. It copies unedited components exactly. ACL
reserved fields and ACL trailing bytes survive edits. Unreferenced descriptor gaps or tails
are refused because no relocation policy has been established. Nothing edits shared bytes.

`MicrosoftObservableProjector` is a read-only projection. It implements reviewed D13
normalizations plus the separately approved known-entry ordering/import-compaction policy: six recognized ACE families in the correct ACL kind, exact SID/GUID size,
known flags, inactive IO drop, NP clearing and explicit DACL object placement within the
same qualifier group. Inherited order is preserved. Original bytes and write intent remain
unchanged. NULL DACL getter projection is absent; owner/group/SACL changes in the raw engine
retain the original NULL representation.

## Implemented operations and evidence

- Add, Set, Reset, Remove, RemoveSpecific and RemoveAll dispatch for access/audit sections;
  explicit SID purge, owner/group replacement and protection changes.
  Detached protection preserves inherited flags/order when requested, as the new Windows
  recordings establish; removing inheritance drops the entries.
- Mask OR, complementary container scopes and same-shape audit success/failure merge;
  no merge across qualifier or object/non-object families.
- Recorded asymmetric mask Add can absorb an incoming qualified object mask into an
  existing object ACE without ObjectType when all incoming qualified bits are already
  covered, flags and inherited GUID match. New global bits are ORed into the existing
  mask, retaining its GUID shape. Reverse direction, uncovered qualified bits and different
  audit flags keep separate ACEs. Absorbed no-ops preserve raw bytes and prior intent.
- Add now follows three coherent stages: mask merging with matching GUID values or
  absent-existing-OT containment; audit merging with equal mask/inheritance/GUID values;
  then valid DS scope union with matching IOT values or absent existing IOT. Matching
  explicit type/SID is required throughout. Existing GUID layout is retained, and value
  equality stays local to Add. The 101-case qualifier/value-presence extension covers
  the reported Deny/Audit scope and present-empty OT mask analogues without changing
  SACL ordering, import compaction or specific-removal identity.
- Remove splits remaining mask, audit and container propagation dimensions; returns false
  atomically for unrepresentable narrowing and true for no-match access removes.
- Object-specific subtraction qualifies only the measured DS rights; global rights still
  match across ObjectType GUIDs. Split ACEs drop inapplicable GUID fields while keeping
  their ACE family. Object Add/Set/Reset upgrades revision 2 to 4; common Add preserves it.
- Recorded removal precedence skips disjoint self/descendant scopes before GUID narrowing;
  inherited-object GUID narrowing applies only when both ACEs have CI. Audit outcome
  disjointness remains after GUID checks.
- Distinct inherited-object GUIDs share no descendant scope: an All request can subtract
  self while retaining the original GUID-qualified descendants; descendant-only requests
  and descendant-only existing ACEs are no-ops. Disjoint ObjectType rights skip before IOT
  matching; overlapping global rights still subtract self. Thirty-two new DACL/SACL
  observations cover mixed masks, immediate/deeper descendants, audit splitting and
  missing-ObjectType conflict precedence after inherited-GUID no-op filtering.
- Common and object ACE OI propagation uses DS semantics: OI contributes no propagation dimension,
  but permission/audit residuals retain its raw bit. Recomputed propagation omits OI.
  OI with NP/IO but without CI cannot be subtracted and returns false atomically unless
  the operation is disjoint. Sixty-four observations cover every odd low flag combination
  for Add and Remove in both ACL kinds. A further 192 cases cover OT-only, IOT-only
  and both-GUID object ACEs across all eight OI flag combinations, three Remove scopes
  and same-mask Add. Merge retains original GUID fields; removal cleans each residual's
  inapplicable GUIDs. This does not authorize global OI normalization.
- Three eight-step sequences combine object OI, distinct IOT/global-right subtraction,
  no-ops, protection/unprotection, inherited-entry removal and RemoveSpecific. The SACL
  sequence replaces all same-SID explicit splits with Set; it was originally recorded
  under the earlier conservative multi-entry policy. Original bytes and accumulated section intent are asserted.
- Absent/NULL SACL removals return true with modified=false and no write intent.
- Set/Reset/Purge/RemoveAll keep inherited entries and target explicit SID/qualifier across GUIDs.
- Absent/NULL DACL materialization is DACL-operation-specific, preserving original raw state.

`AclMutationReplayTests` uses literal pinned Microsoft Windows outputs for B4/B6, C1–C3,
D1/D2, E1/E2, F1 and G1–G3, plus 1,385 recorded observations (1,353 operation/getter steps and 32 import projections) including all audit
operation families and three-piece splits. I2 and J4/J6 projection tests assert exact
allowed results or explicit refusal of unapproved movement/loss. `MicrosoftObservableProjectorTests` exercises exact D13
predicates and raw/projection separation. `AclMutationEngineTests` checks atomic refusal,
unknown-data preservation outside changed ACLs, overlap, bounded sizes and deterministic
safe mask algebra. Existing codec/SID tests remain part of the explicit offline filter.

## Deferred and conservative boundaries

This draft does not claim completion of all issue 226 acceptance criteria.

Known-entry ordering and projection-only import compaction now follow the separately approved
policy. `AclCanonicalizer` preserves native pivot/tie behavior and inherited order. Multi-entry
SACL mutations are supported for understood entries; imports perform a single adjacent
compaction pass. No live edit performs blanket compaction.

The internal `ModifyProjected` bridge retains live entries and their original contributor
occurrences separately from raw storage. All 258 fresh bridge outcomes now match, including
140 changes, 114 true no-ops and four unchanged false returns. Eight 26-step sequences use
retained state through getters, subsequent edits, failed edits, owner/group and other-ACL
changes. The former eight pairing-boundary refusals are resolved without changing policy.

Projected rule operations, purge and protection preserve provenance. Raw mutations of the
same retained ACL explicitly refuse; use projected counterparts rather than silently resetting
state. A new engine constructed from raw storage is an explicit new import and may regroup
entries. Section-local observable reads leave opaque opposite ACLs uninterpreted; the full
observable getter explicitly requests both sections. See the [policy document](issue-226-ordering-policy.md).
Unrecorded accepted inputs may still differ; gap/orphan relocation and unknown semantics
remain unresolved. Public/LDAP integration is not included.

- A changed ACL containing opaque/callback/unknown flags or recognized ACE trailing payload
  refuses as a whole. Owner/group or another section may still change while those bytes stay
  exact. This is intentionally narrower than Microsoft's H2 unrelated-add behavior.
- Full conditional ACE semantics, object-right-specific matching beyond the recorded shape
  cases, generalized normalization beyond the measured import pass are not established
  by the current recordings. Recognized common/object OI combinations use DS propagation
  rules; invalid overlapping propagation returns false without publication.
  Additional detached Windows recordings are required before expanding parity claims. No effective-access evaluator is claimed.
- Active zero-mask and audit-without-success/failure projection are refused; only the exact
  inactive D13 exception may drop them. Meaningful labels/audit entries never disappear.
- Descriptor gap/tail relocation, public exception/constructor parity and write-mask policy
  are outside the implemented evidence. This engine makes no DirectoryEntry rollback promise.

Known complementary-scope and other measured common/object import compaction is supported
only in the observable import projection. Mutation normalization stays separate, preserving
recorded live split-restore states and unrelated raw duplicates. Original bytes and section
intent are never replaced by an imported recording. `RequestedDescriptorHex` is checked
independently from live `InputHex` and explicit Import observations.

## Validation and Windows isolation

Only the five named fixture-free functional test classes run. The new workflow uses
`windows-2025`, ordinary GitHub-hosted runtime, .NET 8 and 10, `contents: read`, a push
trigger restricted to `bro/issue-226-acl-mutation-engine`, and TRX/oracle artifacts. It has
no AD secrets, environment, OU steps, privilege changes or Persist calls. Existing Samba
and self-hosted differential workflows are untouched.

The copied standalone oracle records detached Microsoft System.DirectoryServices 9.0.0
behavior. The workflow compares the fresh observation bodies against the committed
recordings, and the portable replay assertions compare against the same evidence. Process
exit alone is not treated as parity. Exact head validation and run URLs are reported in the draft PR.

The exact seeded recording provenance is documented in the oracle README. Tests replay actual Windows outputs on
both Linux and Windows, not generated expectations. The original J6 examples include
orphaned bytes after aliasing offsets, so those exact inputs refuse repacking; compact
shared-storage examples successfully unshare and preserve all referenced components.

Current offline filter: 1758 replay cases (including 1,385 recorded observations, 258 projected reconciliation
cases, retained sequences and cross-runtime equality), 78 projection cases, 102 mutation safety
cases, 139 codec cases and 21 SID cases: 2098 total. The safety suite includes 100 deterministic disjoint-mask
iterations (seed 2262026); projector predicates exhaust all 256 flag bytes across six types
and both ACL kinds. These iteration counts are not separate xUnit case counts.
