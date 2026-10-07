# Known-ACE ordering and projection compaction

The user approved this next slice on 2026-10-07: verified Microsoft reordering of fully
understood entries during explicit edits; import compaction initially affects only the
observable representation; write preparation preserves unrelated original entries and
unknown payloads. This is an amendment to the previous I2 ordering deferral, not permission
for arbitrary normalization, loss or relocation.

Eligibility remains exact recognized allow/deny/audit common/object ACEs in the correct ACL
kind, validated known flags and GUID/SID layout, and no unexplained ACE trailing payload.
Unknown/callback/conditional payload interpretation remains outside this slice.

- Raw parsing and original provenance remain lossless.
- Read/import projection may apply recorded ordering and compaction without creating intent.
- Known explicit ACE ordering may change during a requested section edit, including measured
  equal-key tie movement. Inherited order and existing ACE contents remain intact except
  where the requested operation or the previously approved exact D13 normalization changes them.
- Import compaction must not become a blanket live-edit compaction pass. An unrelated edit
  preserves original redundant ACEs. A semantic edit that cannot be reconciled with original
  entries refuses atomically with a concrete reason instead of writing a lossy projection.
- Owner/group/unrelated ACL changes never write incidental ACL normalization. Return/modified
  flags do not themselves establish write intent. Failed and proven no-op operations preserve
  state and prior intent.
- Descriptor gap/orphan relocation, arbitrary unknown-data loss, public API, LDAP/resolver/
  interop integration and effective access are not included in this implementation slice.

Microsoft recordings are evidence, not an automatic allowlist. The initial new probe is
`OrderingSequences.cs`: 88 isolated mutation calls, 24 stateful calls and 32 import cases.
The final implementation evidence and any unresolved reconciliation cases must be added
before the slice is described as complete.


## Implemented evidence and reconciliation boundary

Probe commit `7ba9afbcdea4f58c57deacad1a9b943c7606588f`, Windows run
[37658872363](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37658872363),
recorded 144 additional observations. Both runtimes agree on all 919 observations and the
previous 775 are unchanged. The probe run intentionally failed freshness against the old
baseline, while both portable test steps passed.

`AclCanonicalizer` uses recorded family/SID ordering and native pivot/tie behavior; inherited
entries retain their original order. Add merges in place or appends then sorts. Import uses
one adjacent compaction pass, not fixed-point minimization: three compatible entries can
become two. Always project from the retained raw import baseline; re-importing an already
projected value is a distinct operation and must not be confused with repeated reads.

## Retained live state and contributor provenance

`Modify` edits raw/live ACEs on a raw-mode engine. `ModifyProjected` establishes a retained
Microsoft-style live ACL together with the raw contributors of each projected entry.
These are separate immutable values: raw `Descriptor`, lossless `OriginalDescriptor`,
section intent, and lazy per-section live/provenance state. Duplicate occurrences are
tracked by their positions in contributor arrays, never rediscovered by SID/byte lookup.

All six projected rule operations, `PurgeProjected`, and `SetProtectionProjected` operate
on retained live groups. A complete expected operation is validated before any result is
published. Unchanged groups preserve every contributor; changed groups preferentially
distribute the edit over originals, reconstructing only an explicitly changed group when
necessary. A split receives distinct new groups. View sorting moves the associated groups
together. Publication validates both binary representations and requires the flattened
contributors to match the exact raw ACL. A retained raw-ACL fingerprint guards against
stale provenance. No published state is mutated in place.

`GetObservableAcl(section)` reads only the requested section. Editing/reading known SACL
state beside an opaque DACL never projects that DACL. `GetObservableDescriptor()` explicitly
requests both ACL projections and therefore keeps their strict validation. Owner/group and
other-ACL changes carry retained state forward unchanged. No-op/failed operations return
the same engine with exact raw bytes and intent; an object Add that upgrades revision two
to four is a header change, not a no-op.

### Explicit mode and re-import boundaries

Raw `Modify`, `Purge`, and `SetProtection` refuse for an ACL with retained projected state;
their projected counterparts preserve that state. They do not silently reset provenance.
Raw operations on the other ACL and owner/group edits remain available. Constructing a new
engine from the current raw `Descriptor` explicitly starts a new import/provenance baseline,
with no write intent. There is no directory save/reload operation in this internal slice.

A retained live view need not equal a fresh import of raw storage. For example, four allow
ACEs for `S-1-5-21-1-2-3-1001`, flags zero, masks `[0x10,0x20,0x40,0x80]` import as
`[0x30,0xC0]`. Projected Remove of `0x10` retains raw `[0x20,0x40,0x80]` and live
`[0x20,0xC0]`, with `0xC0` mapped to the untouched `0x40,0x80` contributors. Subsequent
RemoveSpecific(`0xC0`) removes exactly those two occurrences. Repeated getters do not import
again. An explicitly new engine imports the raw value as `[0x60,0x80]`; that is a separate
operation. No redundant ACE is invented and no unrelated pair is compacted during editing.
The earlier global re-import equality check was unnecessarily restrictive and is removed.

## Actual Windows evidence

`ReconciliationSequences.cs`, probe commit `91df3c9ea36d2fe500b6571ad485c5a2d2c06206`,
[run 37670943012](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37670943012),
recorded 258 fresh-import rule calls. All outcomes now replay through the projected bridge:
140 byte changes, 114 true no-ops, and four false/modified=false unchanged removals. None
throws. The eight previously refused triple/four-entry edits now retain live state successfully.

`ProjectedLiveSequences.cs`, probe commit `45c95cc9b2524e5606bda94fc67e9c86c93d6640`,
[run 37674000374](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37674000374),
adds 208 steps in eight retained-object sequences. They include the first subset removal,
repeated collection/serialization getters, a failed conflicting-GUID removal, owner/group
and opposite-ACL edits, exact removal of the remaining compacted group, further Add/Remove/
RemoveSpecific, Set/Reset/RemoveAll, protection and purge. Both runtimes agree on all 1,385
observations; all earlier 1,177 remain unchanged. Probe freshness checks deliberately fail
against the preceding baseline while portable tests pass.

Replay separately checks raw/live native operations and end-to-end projected operations.
Every unchanged fresh bridge row asserts same-engine identity, exact raw bytes and intent.
Every retained sequence checks all older raw/live snapshots and accumulated intent after
every step. Dedicated safety cases cover equal-byte occurrences, split residual mappings,
explicit re-import, raw-mode rejection, prior-intent failure and opaque opposite ACLs.

Exact-head Linux/Windows results are recorded in the draft PR. No preservation-policy
relaxation is needed for the former eight cases. Unknown/trailing payload semantics,
descriptor gaps, broader unrecorded parity and later public integration remain outside the
claim; passing recordings does not establish universal parity.
