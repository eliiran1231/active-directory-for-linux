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
reconciliation entrypoint for rules selected from the current import projection. It records
original contributors during the exact single adjacent compaction pass; duplicate occurrences
remain distinct. It first validates the complete projected operation. Unchanged groups keep
all original entries. Changed groups preferentially distribute the edit over their originals;
when that cannot reproduce the changed projected group, only that explicitly targeted group
is reconstructed. RemoveSpecific deletes the contributors of exact projected matches, never
all entries for a SID. Final whole-ACL reprojection must match the requested projected outcome
before publication. No-op calls preserve raw entries and prior intent, while a required
revision-2 to revision-4 object-Add upgrade still publishes the header change.

This is a reconciliation rule for explicitly changed groups, not permission to compact
unrelated originals. Known-entry ordering remains subject to the approved ordering policy.
Unknown/trailing payloads, noncanonical mutations and descriptor gaps retain their existing
refusals. Whole-identity operations retain their raw targeting behavior. Public integration
must distinguish raw/live operations from fresh-import projected operations.

## Fresh reconciliation evidence and remaining policy boundary

Probe commit `91df3c9ea36d2fe500b6571ad485c5a2d2c06206`, Windows
[run 37670943012](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/37670943012),
adds 258 actual Microsoft observations from `ReconciliationSequences.cs`. Both runtimes agree
on all 1,177 observations; the earlier 919 are unchanged. The probe intentionally fails
freshness against the previous recording baseline. All 258 Microsoft calls succeed.

The portable raw/live engine replays all 258 calls. The separate projected-to-raw bridge
successfully reconciles 250 and explicitly refuses eight triple/four-entry subset removals
in both ACL kinds, with/without neighbors. No expected Microsoft output was invented or
replaced with a refusal. The negative bridge cases assert original bytes and prior intent.
Coverage includes duplicate/mask/scope/audit/object/present-empty GUID groups, exact/subset/
new-bit additions, exact/subset/absent-bit removal, exact/subset specific removal, unrelated
same-SID GUID groups and different-SID originals, and revision-two object no-ops.

### Exact unresolved witness

Recorded sequence `projected-reconcile-four-False-False-Remove-subset` has four allow ACEs
for `S-1-5-21-1-2-3-1001`, flags zero, masks `[0x10,0x20,0x40,0x80]`. Their single-pass
projection is `[0x30,0xC0]`. Microsoft Remove of mask `0x10` returns true/modified=true and
produces `[0x20,0xC0]`. The effective rule bytes are:

```text
0000240010000000010500000000000515000000010000000200000003000000E9030000
```

The recorded output DACL bytes are:

```text
04005000020000000000240020000000010500000000000515000000010000000200000003000000E903000000002400C0000000010500000000000515000000010000000200000003000000E9030000
```

Preserving the untouched `0x40,0x80` originals leaves raw `[0x20,0x40,0x80]`, which imports
as `[0x60,0x80]`. Every permutation merges two of those masks first, so none can start with
`0x20`. Achieving the exact Microsoft view requires inventing a redundant `0x20` contributor,
compacting the unrelated pair, or relaxing representation/order equivalence. Those policy
changes are not implemented. The current exception identifies the cross-group compaction/
ordering boundary and publishes nothing. This is a precise remaining blocker, not a blanket
refusal of compacted SIDs. The analogous three-entry cases cannot retain two separate
projected entries after deletion without an extra contributor either.

Exact-head Linux/Windows results are recorded in the PR. These cases establish bounded
parity and preservation; unrecorded accepted inputs, unknown semantics and broader public
constructor/exception parity remain outside the claim.
