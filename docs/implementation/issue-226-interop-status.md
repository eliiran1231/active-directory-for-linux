# Microsoft descriptor snapshot and optional companion boundary

The internal, tested D1/D2/D8 boundary now backs the approved optional public
`AdForLinux.DirectoryServices.MicrosoftInterop` companion. The main DLL acquires no Microsoft DirectoryServices
dependency. The later [coherent AD/entry integration](issue-226-entry-persistence-status.md)
is implemented; the descriptions of the original detached slices below do not postpone that cutover.

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

ACL edit-back permits nonzero mask changes and deletion of explicit, uniquely identifiable
live occurrences with exactly one raw contributor. Surviving occurrences retain order, ACE
type/flags, identity and GUID fields. ACL state, revision and reserved fields stay unchanged;
only size/count may shrink for deletion or grow for the separate insertion path below. Existing retained provenance is
validated directly; fresh imports build occurrence-index mappings using only the reviewed
normalization, sorting and single-pass compaction rules. The clean export baseline must equal
the current retained live ACL, and the resulting projection must equal the edited target.

Unchanged merged groups and inactive originals retain their exact raw bytes, including original
NoPropagate bits. Changed merged contributors, duplicate same-shape occurrences, inherited ACEs,
zero masks, merging/ambiguous/inherited additions or removals, splits, reordering, control fields and ambiguous fresh-import
regrouping refuse. Shared ACL objects retain identity; all owners reconcile in one existing
facade transaction or roll back together, including a failure after the other ACL was edited.
Detached replacement requires explicit section intent and a loaded destination baseline under
the [approved contracts](issue-226-persistence-decisions.md); it is never an implicit fallback. This is deliberately
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
with actual Microsoft comparisons on Windows. Portable AD materialization is now integrated with the coherent hierarchy/consumer cutover;
no parallel AD rule hierarchy was introduced.

Next dependencies: overlapping/ambiguous compound edits, revision-changing insertions,
splits, reordering and ambiguous/multiple-contributor edit-back;
additional unrecorded conversion boundaries. Public companion exposure and its exact named
friend relationship were subsequently approved and implemented (see final section).
The [approved persistence contracts](issue-226-persistence-decisions.md) are integrated with
entry transport; live AD and any effective-access evaluator remain outside this slice.
The [remaining compatibility inventory](issue-226-remaining-compatibility.md) separates these
implementation gaps from genuine exposure decisions and live-server validation.
Every existing protected hook remains intact.


## Unique-contributor deletion follow-up

The reconciler accepts an order-preserving subsequence of exported ACE shapes, optionally
with already-supported nonzero mask edits. Every removed occurrence must be explicit,
uniquely identifiable by its non-mask fields and backed by exactly one raw contributor.
Unchanged merged groups and raw occurrences excluded by projection retain every byte,
including NoPropagate flags. Existing retained contributor state is rebuilt from surviving
occurrences; a fresh import keeps its original raw occurrence ordering. Deleting the last
live ACE produces a present empty ACL, never absent or NULL.

The final observable ACL must equal the target bytes before publication. Added ACEs,
reordering, scope/qualifier changes, inherited or merged removals, ambiguous duplicate shapes,
state transitions and changed header/reserved fields still refuse atomically. Shared ACL
identity and existing pending intent survive; failure in a later ACL rolls back every affected
owner and dirty flag. Stale export provenance remains invalid even for an unchanged target.

Thirty-one directed offline cases cover common/object DACL/SACL removal, inactive and merged
raw survivor bytes, shared owners, retained provenance and follow-on edits, existing Owner
intent, empty ACLs, all deletion positions combined with mask edits, refusal boundaries and
compound rollback. Fourteen positive removal cases all failed against the previous mask-only
reconciler. Windows tests perform actual Microsoft CommonSecurityDescriptor/ACL edits; Linux
uses portable detached objects. This does not claim a public companion API or Microsoft AD
transport parity, and changes no native oracle recording or preservation policy.


## Non-merging explicit insertion follow-up

A candidate with more live ACEs takes a separate insertion proof. Every original exported
occurrence must survive byte-identically and in its previous order. Each extra ACE must be
explicit, understood, nonzero, unambiguous and already in its normalized form. Neither direction
of the reviewed merge rules may merge it with a live survivor, any raw original (including
hidden occurrences), or another new ACE. No operation history, scope change or replacement
of an existing occurrence is inferred from a larger candidate.

Placement is deterministic: put each new ACE immediately before the first raw contributor
of its next surviving live group, or at the raw end if no group follows. Copy every original
raw occurrence in its existing order, byte for byte. Multiple new ACEs at one anchor retain
their candidate order. Backward anchors in an independently sorted raw layout refuse rather
than moving survivors. Retained live groups gain only the new single-contributor occurrences;
old groups and their contributor arrays remain intact. The complete resulting projection must
match the edited target before publication. Empty-to-populated *present* ACLs are supported;
absent/NULL transitions and revision/header changes are not implicit insertion operations.

Forty-seven new offline cases cover common/object DACL/SACL insertions at every position,
merged/inactive/inherited raw survivors, shared descriptor identity, retained contributor
state and follow-on mask edits, pre-existing Owner intent, empty ACLs, multiple insertions,
backward-anchor and raw-capacity refusal, normalization/merge/unknown/zero/inherited refusal, mixed-change
refusal and rollback after another section fails. All 22 selected successful insertion cases
failed against the previous implementation. Existing general-addition refusal fixtures now
specifically assert inherited-addition refusal; positive cases are no longer mislabeled as
unsupported. Windows executes actual Microsoft detached AddAccess/AddAudit operations.
No native recording, preservation policy or uncertain-write behavior changes.

The [exact companion proposal](issue-226-microsoft-companion-proposal.md) specifies package,
assembly, namespace, extension signatures, snapshots, one-success edit sessions, disposal,
authority separation and friend access. Those public names and wrappers were subsequently approved and implemented; see the final
section. The architecture and preservation rules are unchanged.

## Insertion canonicality correction

Independent review of `aea54572a3ded6cb848168fa6a04791de0779f03` found that projection
byte equality alone was insufficient: the read projector deliberately preserves a known
noncanonical ACL. A candidate appending Deny after Allow, or an explicit ACE after inherited
ACEs, could therefore pass insertion while the shared CommonAcl retained its immutable
`IsCanonical == true` flag. That disagreed with a fresh Microsoft import and left future
mutator guards inconsistent.

Insertion now requires canonical qualifier/inheritance order in both baseline and candidate
at the raw planner. Independently, facade edit-back validates the candidate with the same
canonicality classifier used at construction and requires the source's cached canonicality
to be true before replacing its ACL bytes. The classifier inspects raw order without sorting.
No survivor is moved and no readonly flag is changed to make a candidate appear acceptable.
Unchanged detached exports still remain no-ops; modified noncanonical ACLs explicitly refuse.

Twenty regressions all failed on the preceding implementation. They cover common/object
Deny-after-Allow DACLs, explicit-after-inherited DACLs and SACLs, fresh and retained contributors,
direct planner calls, shared ACL aliases, pre-existing intent, subsequent valid mutators,
stale provenance, compound rollback and successful retry with the same restored provenance.
On Windows, tests create the candidate through actual Microsoft RawAcl insertion, then verify
that a fresh Microsoft CommonSecurityDescriptor reports noncanonical, preserves the bytes,
and throws InvalidOperationException on a future AddAccess/AddAudit. Linux exercises the same
contract with portable objects. This is new directed runtime evidence, not an edited native
recording. Public companion proposal/exposure and all preservation policies are unchanged.


## Atomic combinations against original provenance

The reconciler now uses one original occurrence map for unique-contributor mask changes,
unique explicit deletions and non-merging explicit insertions. Matching uses original non-mask
fields and original order. A deletion never renumbers a later anchor, and an intermediate mask
result never becomes a new match baseline. Unchanged duplicate shapes can only survive in
original order; changing or deleting one still requires a unique original occurrence and a
single contributor. Unchanged merged groups and hidden raw originals remain byte-identical.

Only the final candidate is published. New ACEs must remain non-merging in both directions
against original raw/live data, final survivors and other insertions. A new ACE sharing a SID
with any mask-changed or deleted original refuses: a value diff cannot distinguish independent
insertion from scope/qualifier replacement or splitting that identity. This conservative
boundary does not infer broader replacement intent. Raw placement keeps the existing stable
next-survivor anchors and original survivor order, skipping only proven deletions. Canonicality,
headers, capacity, unknown storage, final projection and source freshness remain checked.
Retained groups use the surviving original contributor indices plus new single contributors.

Fifty new deterministic cases cover common/object DACL/SACL combinations with increasing,
unchanged and decreasing counts, fresh/retained provenance, mask+insert, delete+insert and
multiple mixed changes. All 32 selected positive combinations failed on the preceding head.
Tests verify exact raw survivor bytes (including inactive, inherited, merged and NoPropagate
originals), shared identity, pre-existing intent and later mutation. Compound Owner/Group/DACL/
SACL publication is covered, as are rollback after a later ACL failure, a shared owner's
unknown-layout resize refusal and retry using restored provenance. Replacement/split ambiguity,
merged edits, inherited removal, opaque data and noncanonical order still refuse. Windows
executes actual Microsoft raw mask edits, detached Remove/Add operations and owner/group setters;
no native oracle recording is altered. Earlier mixed-operation refusal fixtures now test
unsupported scope/qualifier replacement instead of refusing the newly proven independent case.

## Approved optional public companion

The user approved `AdForLinux.DirectoryServices.MicrosoftInterop` as package, assembly and
namespace. The optional Windows-targeted project exposes the exact documented extensions,
immutable defensive-copy snapshot and disposable one-success edit session. No change to the
main/AccountManagement dependency graph or existing AD class names is required.

Conversion calls actual Microsoft constructors/serializers and verifies the resulting fields
or binary image. Snapshot export reuses the strict existing allowlist. Partial AD import
coverage now intersects the wrapper's explicit masks; stored sections never promote coverage.
Import carries no resolver, entry authority or inherited pending intent. Unknown rule types,
lossy descriptor import/export and unsupported edit-back still refuse.

A session owns copied data, GUID/version tokens and a Microsoft object, never the source
wrapper or a resolver/connection. A successful local ApplyTo consumes it, including no-op;
failed apply leaves it retryable only while the source remains current. Disposing is idempotent,
never applies/saves, and invalidates session getters/application. Previously returned data
remains usable. The simple ToMicrosoftObject path remains independent of edit sessions.

Public tests cover copy isolation, partial coverage, immutable snapshots, actual AD-security
roundtrips, disposal and source collection, retry/consumption/staleness, strict rule subtype/
field conversions, collection order/duplicates and refusal of custom/non-AD rules. Compiled
examples distinguish local application from explicit CommitChanges; no save runs in tests.
Package verification checks exact core/native dependency versions and absence of the optional
companion/native DirectoryServices dependency from core and AccountManagement.

This implements source exposure only, not a NuGet release. Explicit Add server validation,
ambient identity pinning, context-helper exposure and unknown SDDL boundaries remain separate.

## Public snapshot and edit-session review corrections

Snapshots now retain all accepted pending intent independently of retrieved coverage. A
detached partial native import followed by an inherited/base SetOwner, SetGroup, binary/SDDL
section import or protection edit no longer silently clips the pending section from the
snapshot. Existing typed ACL guards and detached setter behavior remain unchanged. Export
still requires complete coverage, and assigning pending edits outside known source/destination
coverage still refuses. This corrects metadata, not an LDAP write bypass.

Reconciliation now validates the caller-supplied wrapper's current bound resolver lifetime
through atomic publication, even for no-op. Revoked entries/contexts and mismatched raw read
origins refuse without changing source bytes, generation, pending intent or attachment.
The temporary lock order is wrapper write lock, owner lifetime, then shared mutation gate;
caller-held shared gates refuse before borrowing a lifetime. No authority is stored in a
session, and no lookup, transport or caller factory runs in publication. Directed races
exercise revocation before publication and lifetime retention through publication while an
independent wrapper continues making progress.
