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
