# Internal Microsoft descriptor snapshot boundary

This implements an internal, testable part of approved D1/D2/D8. It does not choose final
public helper, assembly or package names. The optional Microsoft companion remains the
approved packaging destination; the main DLL acquires no Microsoft DirectoryServices
dependency. Existing public AD classes and transport remain unwired.

`ObjectSecurity.Interop.cs` captures current raw bytes, original read bytes, current observable
bytes, retrieved sections, pending section intent, wrapper identity and descriptor generation.
The snapshot contains copied data only. It holds no descriptor/wrapper reference, resolver,
credentials, connection, callback, read-origin authority or persistence capability. All binary
accessors return copies. A snapshot is not permission to write to a directory.

Internal detached export and provenance-bearing export are separate entry points. A companion
supplies its actual target constructor and serializer; neither callback is retained, and both
run outside portable locks. Before returning a target, the boundary validates raw contributors
against the existing reviewed projection allowlist and compares the actual target's serialized
post-import baseline with the expected fresh projection of the portable live view. This keeps
fresh-import compaction separate from raw contributors and never turns conversion into intent.
The tests use real framework `CommonSecurityDescriptor` objects on Windows. Linux tests use
the portable target and separately verify that actual framework construction is unsupported.
These descriptor tests do not claim Microsoft AD-security conversion; the internal value/rule
conversion boundary below is tested separately.

Strict export currently refuses partial retrieval, unexplained descriptor storage, unsupported
control/reserved fields, hidden ACL storage and unverified ACE/ACL payloads. Callback ACEs are
not declared universally unsupported by Microsoft: this boundary refuses them because its
current verified projector cannot prove their conversion. Approved inactive recognized access
and audit ACE omission, NoPropagate clearing, known-ACE ordering and projection compaction use
the existing narrow projector; raw bytes remain intact. No diagnostic/lossy export is added.

Edit-back checks source wrapper identity, shared descriptor generation and identity attachment
before considering even an unchanged target. An unchanged post-import baseline is a no-op,
including edit/revert and normalized exports. Repacked referenced components compare equal;
unexplained padding does not. Supported owner/group differences update only those raw sections,
preserving ACL originals, existing live contributor provenance and absent/NULL distinctions.
Updates run inside the existing facade transaction, with dirty flags rolled back on failure.
Two wrappers sharing a descriptor observe its edits and generation invalidation, but cannot
exchange export provenance. Existing pending edits are neither cleared nor reclassified.

ACL edit-back now permits only nonzero mask changes on explicit, uniquely identifiable live
occurrences with exactly one raw contributor. ACL state, header, revision, count, order, ACE
type/flags, identity and GUID fields must remain unchanged. Existing retained provenance is
validated directly; fresh imports build occurrence-index mappings using only the reviewed
normalization, sorting and single-pass compaction rules. The clean export baseline must equal
the current retained live ACL, and the resulting projection must equal the edited target.

Unchanged merged groups and inactive originals retain their exact raw bytes, including original
NoPropagate bits. Changed merged contributors, duplicate same-shape occurrences, inherited ACEs,
zero masks, additions/removals, splits, reordering, control fields and ambiguous fresh-import
regrouping refuse. Shared ACL objects retain identity; all owners reconcile in one existing
facade transaction or roll back together, including a failure after the other ACL was edited.
Full replacement is a separate pending policy and is never a fallback. This is deliberately
not complete ACL edit-back or a reconstruction of the caller's operation history.

The 36 new offline cases cover actual detached objects, unchanged and normalized exports,
owner edits, audit/raw contributor retention, stale/shared/unrelated provenance, unread sections,
rebind invalidation, copy isolation, pre-existing intent, external callback lock isolation,
unsupported edit atomicity, unsafe conversion loss and opaque/unknown-data refusal. Windows
execution is required in addition to Linux tests; exact-head workflow evidence is reported on
PR228 after publication. Existing native recordings are unchanged.

## Internal identity, rule and collection conversion

`InteropValueCodec` stages strict scalar/field conversion without choosing public names. Numeric
SID bytes and NTAccount spelling are copied exactly; no translation, resolver, token or directory
operation runs. Actual Microsoft identity construction has a Windows guard and a field round-trip
check. The main project gains no package reference; the helpers use existing framework identity
types. Their eventual public exposure belongs to the approved optional companion.

Immutable identity/rule snapshots retain the full signed rights mask, inherited state,
inheritance/propagation flags, access qualifier or audit bits, both GUIDs and their presence
flags. Factory conversion validates every returned field before publishing. Import creates
internal field-only portable common/object access/audit rules and refuses constructor
normalization, including present-but-zero GUID distinctions that rule constructors cannot keep.
Unknown consumer rule subclasses refuse unless the internal caller explicitly opts into
field-only conversion; subtype behavior and extra state are never claimed to be copied.

Collection conversion copies elements in order with multiplicity, validates all portable inputs
before invoking target factories and returns only a complete collection. Neither direction
returns a partial result. External factory/inspection callbacks are not retained and do not run
under the portable mutation gate. Snapshots contain no resolver or credential capability.

An additional 62 directed cases cover SID/name copies, 32 common/object access/audit field
combinations, collections, unsupported fields/subclasses, target loss, callback lock refusal,
unique DACL/SACL mask edits, unrelated merged/inactive raw preservation, retained provenance,
shared identity and compound rollback. Windows uses actual framework identities, subclasses of
framework rule bases, and native CommonSecurityDescriptor SetAccess/SetAudit calls; Linux uses
controlled portable values. Those tests alone do not claim Microsoft AD-rule conversion or
all-seven-specialized-subtype coverage. Native oracle recordings remain unchanged.

The [AD rule matrix](issue-226-ad-rule-interop-status.md) now stages exact subtype snapshots
and current-hierarchy conversion for all nine AD rule classes and their 45 constructors,
with actual Microsoft comparisons on Windows. Public portable AD materialization still waits
for coherent hierarchy/consumer cutover; no parallel AD rule hierarchy was introduced.

Next dependencies: ambiguous/multiple-contributor and structural ACL edit-back; Microsoft
AD-security conversion and coherent portable AD-class cutover; reviewed companion friend-access
and final public names. The four pending
persistence policies, live AD and any effective-access evaluator are outside this slice.
Every existing protected hook remains intact.
