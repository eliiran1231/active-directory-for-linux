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
There is no claim that these are Microsoft AD-security or individual-rule converters.

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

Changed ACL bytes or control fields refuse atomically. The missing dependency is an explicit
mapping from a detached target's changed live ACE occurrences back to retained raw contributors
(including merged/split occurrences and inactive raw originals). A final-buffer diff alone is
not a proven operation journal. Full replacement is a separate pending policy and is not used
as a fallback. Thus this slice does **not** claim complete ACL edit-back or public interop.

The 36 new offline cases cover actual detached objects, unchanged and normalized exports,
owner edits, audit/raw contributor retention, stale/shared/unrelated provenance, unread sections,
rebind invalidation, copy isolation, pre-existing intent, external callback lock isolation,
unsupported edit atomicity, unsafe conversion loss and opaque/unknown-data refusal. Windows
execution is required in addition to Linux tests; exact-head workflow evidence is reported on
PR228 after publication. Existing native recordings are unchanged.

Next dependencies: contributor-aware ACL edit-back; strict SID/name/rule/collection converters;
Microsoft AD-security conversion after coherent portable AD-class cutover; reviewed companion
friend-access and final public names. The four pending persistence policies, live AD and any
effective-access evaluator are outside this slice. Every existing protected hook remains intact.
