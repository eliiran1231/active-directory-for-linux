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

The existing `Modify` entrypoint edits raw/live ACEs. `ModifyProjected` is the explicit internal
reconciliation entrypoint for rules selected from an import projection. It never replaces
raw state with the projection. Add/Remove/RemoveSpecific targeting a SID whose original
entries compact are conservatively refused before publication. Set/Reset/RemoveAll have
whole-identity/qualifier targets and operate directly on the raw originals. Edits to another
SID preserve the redundant original entries exactly. This boundary is deliberately more
conservative than Microsoft and remains an integration requirement for future callers;
there is no public bridge or DirectoryEntry wiring in this slice.

Sixteen additional safety cases cover unrelated raw duplicates, compacted-identity refusal
with prior intent, coarse reconciliation, known SACL ordering with reserved/tail data and an
opaque neighboring DACL, and noncanonical SACL preservation/refusal. Existing unknown/trailing
refusals remain. The updated I2 matrix now accepts 16 DACL and nine SACL recorded outputs;
six excluded DACL payload/flag cases still refuse.

The final PR reports exact-head Linux/Windows evidence. The reconciliation refusal, protected
unknown payloads, descriptor gaps/orphans, and untested accepted combinations remain explicit
limitations; passing the recorded cases does not establish universal parity.
